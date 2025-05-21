#!/usr/bin/env python
import os
import sys
import struct
import numpy as np
import pandas as pd
import json
import warnings
from collections import defaultdict
from scapy.all import rdpcap, UDP, IP
from tensorflow.keras import models
import tensorflow as tf
import joblib
from pymongo import MongoClient

def load_custom_types(mongo_uri: str,
                      db_name: str,
                      coll_name: str) -> dict:
    """
    Connects to MongoDB and returns a dict mapping each custom-type name
    to its definition:
      {
        "<type_name>": {
          "fields": [ { name, size, type, size_field, num_elements, is_bitfield }, … ],
          "total_size": <int>
        },
        …
      }
    """
    client = MongoClient(mongo_uri)
    coll   = client[db_name][coll_name]
    result = {}

    for doc in coll.find():
        type_name  = doc['name']
        total_size = int(doc.get('totalSize', 0))
        fields     = []
        for f in doc.get('fields', []):
            fname = f['name']
            fsize = int(f['size'])
            ftype = f['type'].lower()

            # array inside custom type?
            if ftype == 'array':
                base = f['arrayType']
                ne   = int(f['arrayCount'])
                fields.append({
                    'name':         fname,
                    'size':         fsize,
                    'type':         f'array of {base}',
                    'size_field':   '',
                    'num_elements': ne,
                    'is_bitfield':  False
                })

            # bitfield?
            elif ftype in ('bitfield', 'bit'):
                fields.append({
                    'name':         fname,
                    'size':         fsize,
                    'type':         'bitfield',
                    'size_field':   '',
                    'num_elements': 0,
                    'is_bitfield':  True
                })

            # primitive
            else:
                fields.append({
                    'name':         fname,
                    'size':         fsize,
                    'type':         ftype,
                    'size_field':   '',
                    'num_elements': 0,
                    'is_bitfield':  False
                })

        result[type_name] = {
            'fields':     fields,
            'total_size': total_size
        }

    return result


custom_types = load_custom_types(
    'mongodb://localhost:27017/',
    'custom_types_db',
    'customtypes'
)

##########################################
# פונקציה לטעינת הגדרות פרוטוקול מקובץ TXT
##########################################
def load_protocol_definitions(file_path: str,
                              custom_types: dict) -> pd.DataFrame:
    """
    Reads a protocol TXT where the first non-empty line is the field count,
    and each subsequent line is one of:
      • name size type
      • name size type size_field
      • name size array base_type num_elements
      • name size <custom_type_name>
      • name size array <custom_type_name> num_elements

    Lines whose 'type' matches a key in custom_types (or 'array' + custom)
    are inlined into all their subfields.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [L.strip() for L in f if L.strip()]

    try:
        declared = int(lines[0])
    except ValueError:
        raise ValueError("השורה הראשונה חייבת להיות מספר תקין של שדות.")

    rows = []
    for line in lines[1:]:
        toks = line.split()

        # 1) single custom-type
        if len(toks) == 3 and toks[2] in custom_types:
            outer, sz, typ = toks
            for sub in custom_types[typ]['fields']:
                rows.append({
                    'name':         f"{outer}.{sub['name']}",
                    'size':         sub['size'],
                    'type':         sub['type'],
                    'size_field':   sub.get('size_field',''),
                    'num_elements': sub.get('num_elements',0),
                    'is_bitfield':  sub['is_bitfield']
                })
            continue

        # 2) array of a custom-type
        if len(toks) == 5 and toks[2].lower() == 'array' and toks[3] in custom_types:
            name, sz, _, base, ne = toks
            total, count = int(sz), int(ne)
            elem_size = custom_types[base]['total_size']
            if elem_size * count != total:
                print(f"Warning: {name} total size mismatch: {total} != {elem_size}*{count}")
            for i in range(count):
                for sub in custom_types[base]['fields']:
                    rows.append({
                        'name':         f"{name}[{i}].{sub['name']}",
                        'size':         sub['size'],
                        'type':         sub['type'],
                        'size_field':   sub.get('size_field',''),
                        'num_elements': sub.get('num_elements',0),
                        'is_bitfield':  sub['is_bitfield']
                    })
            continue

        # 3) plain array (built-in base types)
        if len(toks) == 5 and toks[2].lower() == 'array':
            name, sz, _, base, ne = toks
            rows.append({
                'name':         name,
                'size':         int(sz),
                'type':         f'array of {base}',
                'size_field':   '',
                'num_elements': int(ne),
                'is_bitfield':  False
            })
            continue

        # 4) simple fixed/dynamic field
        if len(toks) == 3:
            name, sz, ftype = toks
            rows.append({
                'name':         name,
                'size':         int(sz),
                'type':         ftype,
                'size_field':   '',
                'num_elements': 0,
                'is_bitfield':  ftype.lower() in ('bit','bitfield')
            })
            continue

        # 5) fixed/dynamic with size_field
        if len(toks) == 4:
            name, sz, ftype, sf = toks
            rows.append({
                'name':         name,
                'size':         int(sz),
                'type':         ftype,
                'size_field':   sf,
                'num_elements': 0,
                'is_bitfield':  ftype.lower() in ('bit','bitfield')
            })
            continue

        raise ValueError(f"פורמט שגוי בשורה: {line}")

    if declared != len(rows):
        print(f"אזהרה: מספר השדות המוצהר ({declared}) אינו תואם למספר השדות ({len(rows)}).")
    print(pd.DataFrame(rows))
    return pd.DataFrame(rows)



# טעינת הגדרות הפרוטוקול
protocol_file = "/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server/received_data.txt"
protocol_df = load_protocol_definitions(protocol_file, custom_types)

# בניית מיפוי: שם שדה -> השדה שקובע את הגודל (size_field)
protocol_mapping = dict(zip(protocol_df['name'], protocol_df['size_field']))

##########################################
# פונקציית פירוש קובץ PCAP לפי כתובת IP
##########################################


def parse_pcap_with_ip(pcap_file, protocol_df):
    """
    Parses UDP port 10000 packets from a PCAP and decodes each field,
    including arrays declared as "array of <base_type>".
    Returns dict: src_ip -> list of record‐lists.
    """
    packets = rdpcap(pcap_file)
    data = defaultdict(list)

    for pkt in packets:
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            payload = bytes(pkt[UDP].payload)
            src_ip  = pkt[IP].src if pkt[UDP].dport == 10000 else pkt[IP].dst

            offset = 0
            packet_data = {}
            records = []

            for idx, row in protocol_df.iterrows():
                fname       = row['name']
                fsize       = row['size']
                ftype_descr = row['type']
                sf          = row['size_field']
                ne          = int(row['num_elements'])

                # ---- dynamic-size (size==0) logic unchanged ----
                if fsize == 0:
                    remaining = 0
                    for j in range(idx+1, len(protocol_df)):
                        s = protocol_df.iloc[j]['size']
                        if s != 0:
                            remaining += s
                    dyn = len(payload) - offset - remaining
                    if sf:
                        cand = packet_data.get(sf)
                        try:
                            fsize = int(cand) if cand is not None else dyn
                        except:
                            fsize = dyn
                    else:
                        fsize = dyn

                # ensure we have enough bytes
                if offset + fsize > len(payload):
                    print(f"Not enough data for '{fname}'")
                    break

                # ---- ARRAY case: type == "array of X" ----
                if ftype_descr.startswith('array of '):
                    base = ftype_descr.split('array of ',1)[1]
                    elem_sz = fsize // ne
                    vals = []
                    for i in range(ne):
                        start = offset + i*elem_sz
                        chunk = payload[start:start+elem_sz]
                        if base.lower() == 'int':
                            v = int.from_bytes(chunk, 'big')
                        elif base.lower() == 'float':
                            v = struct.unpack('!f', chunk)[0]
                        elif base.lower() == 'double':
                            v = struct.unpack('!d', chunk)[0]
                        elif base.lower() == 'char':
                            v = chunk.decode('utf-8','ignore').rstrip('\x00')
                        else:
                            v = chunk.hex()
                        vals.append(v)

                    offset += fsize
                    packet_data[fname] = vals
                    records.append({
                        'field_name':   fname,
                        'size':         fsize,
                        'value':        vals,
                        'field_type':   ftype_descr,
                        'num_elements': ne
                    })
                    continue

                # ---- BITFIELD? ----
                if row['is_bitfield']:
                    chunk = payload[offset:offset+fsize]
                    bits  = list(map(int, format(
                        int.from_bytes(chunk,'big'),
                        f'0{fsize*8}b')))
                    val   = bits
                    bcount = sum(bits)

                else:
                    chunk = payload[offset:offset+fsize]
                    lt = ftype_descr.lower()
                    if lt == 'int':
                        val = int.from_bytes(chunk,'big')
                    elif lt == 'float':
                        val = struct.unpack('!f', chunk)[0]
                    elif lt == 'double':
                        val = struct.unpack('!d', chunk)[0]
                    elif lt == 'char':
                        val = chunk.decode('utf-8','ignore').rstrip('\x00')
                    elif lt == 'bool':
                        val = bool(int.from_bytes(chunk,'big'))
                    else:
                        val = chunk.hex()
                    bcount = None

                offset += fsize
                packet_data[fname] = val
                rec = {
                    'field_name':         fname,
                    'size':               fsize,
                    'value':              val,
                    'field_type':         ftype_descr,
                    'size_defining_field': sf,
                    'bitfields_count':    bcount
                }
                if row['is_bitfield']:
                    rec['bit_vector'] = bits
                records.append(rec)

            if records:
                data[src_ip].append(records)

    return data

##########################################
# פונקציות חילוץ מאפיינים
##########################################
def extract_aggregated_features(stats):
    """
    Given a list of record‐dicts from parse_pcap_with_ip,
    returns aggregated sizes and numeric value stats,
    correctly handling array fields whose 'value' is a list.
    """
    import numpy as np

    # sizes of each field‐occurrence
    sizes = np.array([s['size'] for s in stats], dtype=float)

    numeric_vals = []
    for s in stats:
        val = s['value']
        ftype = s['field_type'].lower()

        if isinstance(val, list):
            # unpack all elements
            for elt in val:
                try:
                    numeric_vals.append(float(elt))
                except:
                    numeric_vals.append(0.0)
        else:
            # primitive numeric types
            if ftype in ('int', 'float', 'double', 'long','short'):
                try:
                    numeric_vals.append(float(val))
                except:
                    numeric_vals.append(0.0)
            else:
                numeric_vals.append(0.0)

    numeric_vals = np.array(numeric_vals, dtype=float)

    return {
        'count':      float(len(sizes)),
        'mean_size':  float(sizes.mean()) if sizes.size > 0 else 0.0,
        'std_size':   float(sizes.std())  if sizes.size > 0 else 0.0,
        'min_size':   float(sizes.min())  if sizes.size > 0 else 0.0,
        'max_size':   float(sizes.max())  if sizes.size > 0 else 0.0,
        'mean_value': float(numeric_vals.mean()) if numeric_vals.size > 0 else 0.0,
        'std_value':  float(numeric_vals.std())  if numeric_vals.size > 0 else 0.0,
        'min_value':  float(numeric_vals.min())  if numeric_vals.size > 0 else 0.0,
        'max_value':  float(numeric_vals.max())  if numeric_vals.size > 0 else 0.0,
    }


def create_feature_vector(features):
    return np.array([
        features['count'],
        features['mean_size'],
        features['std_size'],
        features['min_size'],
        features['max_size'],
        features['mean_value'],
        features['std_value'],
        features['min_value'],
        features['max_value']
    ])

##########################################
# פונקציית חלוקה דינמית של הנתונים
##########################################
def segment_stats(stats):
    first_field_type = stats[0]['field_type']
    if first_field_type.lower() in ['int', 'float', 'double', 'long']:
        try:
            numeric_values = np.array([float(s['value']) for s in stats])
        except:
            numeric_values = np.array([s['size'] for s in stats])
        if np.all(numeric_values == 0):
            values = np.array([s['size'] for s in stats])
        else:
            values = numeric_values
    else:
        values = np.array([s['size'] for s in stats])
    
    if len(values) < 2:
        return {"100%": list(range(len(stats)))}
    sorted_indices = np.argsort(values)
    sorted_values = values[sorted_indices]
    diffs = np.diff(sorted_values)
    overall_range = sorted_values[-1] - sorted_values[0]
    if overall_range == 0:
        return {"100%": list(range(len(stats)))}
    max_gap_index = np.argmax(diffs)
    gap = diffs[max_gap_index]
    if gap < 0.01 * overall_range:
        return {"100%": list(range(len(stats)))}
    seg1_indices = sorted_indices[:max_gap_index+1].tolist()
    seg2_indices = sorted_indices[max_gap_index+1:].tolist()
    if len(seg1_indices) >= len(seg2_indices):
        main_indices = seg1_indices
        outlier_indices = seg2_indices
    else:
        main_indices = seg2_indices
        outlier_indices = seg1_indices
    main_percentage = int(round((len(main_indices)/len(stats)) * 100))
    segments = {}
    segments[f"{main_percentage}%"] = main_indices
    segments["100%"] = list(range(len(stats)))
    return segments

##########################################
# פונקציית יצירת DPI באמצעות המודלים המאומנים
##########################################
def generate_dpi(endpoints):
    custom_objects = {'mse': tf.keras.losses.MeanSquaredError()}
    
    dpi_model_is_dynamic = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_is_dynamic_array.h5', custom_objects=custom_objects)
    dpi_model_min_size = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_min_size.h5', custom_objects=custom_objects)
    dpi_model_max_size = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_max_size.h5', custom_objects=custom_objects)
    dpi_model_min_value = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_min_value.h5', custom_objects=custom_objects)
    dpi_model_max_value = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_max_value.h5', custom_objects=custom_objects)
    dpi_model_field_type = models.load_model('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML6/dpi_model_field_type.h5')
    dpi_model_bit_count = models.load_model('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/dpi_model_bit_count.h5', custom_objects=custom_objects)
    le_field_type = joblib.load('/mnt/c/Users/aviv/Desktop/newProject/pythonscripts/ML6/dpi_label_encoder_field_type.joblib')

    dpi_result = {}
    for endpoint_ip, packets in endpoints.items():
        field_stats = defaultdict(list)
        for packet in packets:
            for field in packet:
                field_stats[field['field_name']].append(field)
        fields_dpi = {}
        all_alt_keys = set()
        for field_name, stats in field_stats.items():
            seg_dict = segment_stats(stats)
            field_dpi_alternatives = {}
            for alt_label, indices in seg_dict.items():
                alt_stats = [stats[i] for i in indices]
                features = extract_aggregated_features(alt_stats)
                X_features = create_feature_vector(features).reshape(1, -1)

                pred_is_dynamic = dpi_model_is_dynamic.predict(X_features)
                pred_min_size = dpi_model_min_size.predict(X_features)
                pred_max_size = dpi_model_max_size.predict(X_features)
                pred_min_value = dpi_model_min_value.predict(X_features)
                pred_max_value = dpi_model_max_value.predict(X_features)
                pred_field_type = dpi_model_field_type.predict(X_features)
                pred_bit_count = dpi_model_bit_count.predict(X_features)

                is_dynamic_class = np.argmax(pred_is_dynamic, axis=1)[0]
                is_dynamic_array_pred = bool(is_dynamic_class)

                proto_size_field = protocol_mapping.get(field_name, None)
                if proto_size_field is not None and str(proto_size_field).strip() != "":
                    is_dynamic_array_pred = True
                else:
                    if features['min_size'] == features['max_size']:
                        is_dynamic_array_pred = False

                min_size_pred = float(pred_min_size[0][0])
                max_size_pred = float(pred_max_size[0][0])
                min_value_pred = float(pred_min_value[0][0])
                max_value_pred = float(pred_max_value[0][0])
                
                if np.isnan(min_size_pred):
                    min_size_pred = features['min_size']
                if np.isnan(max_size_pred):
                    max_size_pred = features['max_size']
                if np.isnan(min_value_pred):
                    min_value_pred = features['min_value']
                if np.isnan(max_value_pred):
                    max_value_pred = features['max_value']

                field_type_class = np.argmax(pred_field_type, axis=1)[0]
                field_type_pred = le_field_type.inverse_transform([field_type_class])[0]
                aggregated_field_types = pd.Series([s['field_type'] for s in stats if s.get('field_type') is not None])
                aggregated_field_type = aggregated_field_types.mode()[0] if not aggregated_field_types.empty else "unknown"
                if aggregated_field_type != "bitfield":
                    field_type_pred = aggregated_field_type

                if aggregated_field_type.lower() == 'bitfield':
                    predicted_bit_count = float(pred_bit_count[0][0])
                    if np.isnan(predicted_bit_count):
                        aggregated_bit_count = int(round(np.mean( [ sum(s['value']) for s in alt_stats if isinstance(s['value'], list) ])))
                    else:
                        aggregated_bit_count = int(round(predicted_bit_count))
                else:
                    aggregated_bit_count = None


                size_def_pred = protocol_mapping.get(field_name, None)
                if size_def_pred is None or str(size_def_pred).strip() == "":
                    size_def_pred = None

                field_dpi = {
                    'is_dynamic_array': is_dynamic_array_pred,
                    'min_size': min_size_pred,
                    'max_size': max_size_pred,
                    'min_value': min_value_pred,
                    'max_value': max_value_pred,
                    'size_defining_field': size_def_pred,
                    'field_type': field_type_pred,
                    'bitfields_count': aggregated_bit_count
                }

                # --- if this is a fixed‐length array, override to per‐element lists ---
                # look up this field's protocol definition
                proto_row = protocol_df[protocol_df['name'] == field_name].iloc[0]
                ftype_desc = proto_row['type']
                nelems     = int(proto_row.get('num_elements', 0))
                if ftype_desc.startswith('array of ') and nelems > 0:
                    base = ftype_desc.split('array of ',1)[1].lower()
                    numeric_bases = ('int','float','double','long')

                   
                    min_total_sz     = (min_size_pred)
                    min_elem_sz      = min_total_sz // nelems
                    # build sizes list
                    min_sizes_list   = [min_elem_sz] * nelems

                    max_total_sz     = (max_size_pred)
                    max_elem_sz      = max_total_sz // nelems
                    max_sizes_list   = [max_elem_sz] * nelems

                    # build per-element value lists from alt_stats
                    
                    value_lists  = [
                        [ rec['value'][i] for rec in alt_stats ]
                        for i in range(nelems)
                    ]
                    if base in numeric_bases:
                        min_vals = [ float(min(lst)) if lst else 0.0 for lst in value_lists ]
                        max_vals = [ float(max(lst)) if lst else 0.0 for lst in value_lists ]
                    else:
                        min_vals = None
                        max_vals = None
                    # if the field is a bitfield, we need to count the bits
                    field_dpi['min_size'] = min_sizes_list
                    field_dpi['max_size'] = max_sizes_list
                    field_dpi['min_value'] = min_vals
                    field_dpi['max_value'] = max_vals

                field_type_pred = field_dpi['field_type'].lower()
                numeric_bases = ('int','float','double','long')
                if not any(field_type_pred == nb or field_type_pred.startswith(f'array of {nb}') for nb in numeric_bases):
                    field_dpi['min_value'] = None
                    field_dpi['max_value'] = None
                    # print(f"Warning: field '{field_name}' has type '{field_type_pred}' but is an array of {nelems} elements. Setting min/max values to None.")
                   
                # make all  floats and doubles 3 digits after the decimal
                if isinstance(field_dpi['min_size'], list):
                    field_dpi['min_size'] = [round(float(v), 3) for v in field_dpi['min_size']]
                    field_dpi['max_size'] = [round(float(v), 3) for v in field_dpi['max_size']]
                    if field_dpi['min_value'] is not None:
                        field_dpi['min_value'] = [round(float(v), 3) for v in field_dpi['min_value']]
                    if field_dpi['max_value'] is not None:
                        field_dpi['max_value'] = [round(float(v), 3) for v in field_dpi['max_value']]
                else:
                    field_dpi['min_size'] = round(float(field_dpi['min_size']), 3)
                    field_dpi['max_size'] = round(float(field_dpi['max_size']), 3)
                    if field_dpi['min_value'] is not None:
                        field_dpi['min_value'] = round(float(field_dpi['min_value']), 3)
                    if field_dpi['max_value'] is not None:
                        field_dpi['max_value'] = round(float(field_dpi['max_value']), 3)

                field_dpi_alternatives[alt_label] = field_dpi
                all_alt_keys.add(alt_label)
            fields_dpi[field_name] = field_dpi_alternatives
        
        dpi_alternatives = {}
        for alt_label in all_alt_keys:
            dpi_alternatives[alt_label] = {}
            for field_name, alt_dpi_dict in fields_dpi.items():
                if alt_label in alt_dpi_dict:
                    dpi_alternatives[alt_label][field_name] = alt_dpi_dict[alt_label]
                else:
                    dpi_alternatives[alt_label][field_name] = alt_dpi_dict["100%"]
        dpi_result[endpoint_ip] = dpi_alternatives
    return dpi_result

##########################################
# Encoder מותאם לסוגי NumPy לייצוא JSON
##########################################
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

##########################################
# פונקציית main
##########################################
def main():
    if len(sys.argv) != 3:
        print(json.dumps({'error': 'Usage: python predict_dpi.py path_to_pcap_file.pcap protocol_name'}))
        sys.exit(1)
    pcap_file = sys.argv[1]
    if not os.path.exists(pcap_file):
        print(json.dumps({'error': f'PCAP file {pcap_file} does not exist.'}))
        sys.exit(1)
        
    protocol_name = sys.argv[2]

    print(f"Parsing PCAP file: {pcap_file}")
    endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
    if not endpoints:
        print(json.dumps({'error': 'No valid packets found in PCAP file.'}))
        sys.exit(1)
    print("Generating DPI with dynamic segmentation...")
    dpi = generate_dpi(endpoints)
    final_result = {
        'protocol': protocol_name,
        'dpi': dpi
    }
    output_file = "dpi_output.json"
    with open(output_file, "w", encoding='utf-8') as f:
        json.dump(final_result, f, ensure_ascii=False, indent=4, cls=NumpyEncoder)
    print(f"DPI output saved to {output_file}")

if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()