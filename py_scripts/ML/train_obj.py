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
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras import layers, models
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

    Lines whose ‘type’ matches a key in custom_types (or ‘array’ + custom)
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
protocol_file = "/mnt/c/Users/aviv/Desktop/structs/server/received_data.txt"
protocol_df = load_protocol_definitions(protocol_file, custom_types)

# בניית מיפוי: שם שדה -> השדה שקובע את הגודל (size_field)
protocol_mapping = dict(zip(protocol_df['name'], protocol_df['size_field']))
print(protocol_df)
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
                        elif base.lower() == 'long':
                            v = int.from_bytes(chunk,'big')
                        elif base.lower() == 'short':
                            v = int.from_bytes(chunk,'big')
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
                    elif lt == 'long':
                        val = int.from_bytes(chunk,'big')
                    elif lt == 'short':
                        val = int.from_bytes(chunk,'big')
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
# פונקציות חילוץ ואגרגציה של מאפיינים
##########################################
def extract_aggregated_features(stats):
    """
    Given a list of record‐dicts from parse_pcap_with_ip,
    returns aggregated sizes and numeric value stats,
    correctly handling array fields whose 'value' is a list.
    """

    sizes = np.array([s['size'] for s in stats], dtype=float)

    numeric_vals = []
    for s in stats:
        val = s['value']
        ftype = s['field_type'].lower()

        if isinstance(val, list):
            for elt in val:
                try:
                    numeric_vals.append(float(elt))
                except:
                    numeric_vals.append(0.0)
        else:
            if ftype in ('int', 'float', 'double', 'long', 'short'):
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
# בניית מודלים: רגרסור ומסווג
##########################################
def build_regressor(input_dim):
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(1)
    ])
    model.compile(optimizer='adam', loss='mse')
    return model

def build_classifier(input_dim, num_classes):
    model = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.Dense(64, activation='relu'),
        layers.Dense(32, activation='relu'),
        layers.Dense(num_classes, activation='softmax')
    ])
    model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
    return model

##########################################
# פונקציית אימון המודלים של DPI
##########################################
def train_dpi_subfield_models(pcap_directory):
    pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap') or f.endswith('.pcapng')]
    if not pcap_files:
        print(f"No PCAP files found in {pcap_directory}.")
        sys.exit(1)
    
    aggregated_endpoints = defaultdict(list)
    for pcap_file in pcap_files:
        print(f"Parsing PCAP file: {pcap_file}")
        endpoints = parse_pcap_with_ip(pcap_file, protocol_df)
        for ip, packets in endpoints.items():
            aggregated_endpoints[ip].extend(packets)
    
    all_field_stats = defaultdict(list)
    for ip, packets in aggregated_endpoints.items():
        for packet in packets:
            for field in packet:
                all_field_stats[field['field_name']].append(field)
    
    training_data = []
    for field_name, stats in all_field_stats.items():
        features = extract_aggregated_features(stats)
        sizes = [s['size'] for s in stats]
        # בדיקה האם מוגדר שדה דינמי
        proto_row = protocol_df[protocol_df['name'] == field_name]
        if not proto_row.empty and pd.notnull(proto_row.iloc[0]['size_field']) and proto_row.iloc[0]['size_field'] != '':
            label_is_dynamic_array = 1
        else:
            label_is_dynamic_array = 1 if len(set(sizes)) > 1 else 0

        label_min_size = min(sizes)
        label_max_size = max(sizes)
        numeric_vals = []
        for s in stats:
            try:
                if s['field_type'].lower() in ['int', 'float', 'double', 'long', 'short']:
                    numeric_vals.append(float(s['value']))
                else:
                    numeric_vals.append(0.0)
            except Exception:
                numeric_vals.append(0.0)
        numeric_vals = numeric_vals if numeric_vals else [0.0]
        label_min_value = min(numeric_vals)
        label_max_value = max(numeric_vals)
        aggregated_field_types = pd.Series([s['field_type'] for s in stats if s.get('field_type') is not None])
        label_field_type = aggregated_field_types.mode()[0] if not aggregated_field_types.empty else "unknown"
        
        training_data.append({
            'field_name': field_name,
            'features': features,
            'is_dynamic_array': label_is_dynamic_array,
            'min_size': label_min_size,
            'max_size': label_max_size,
            'min_value': label_min_value,
            'max_value': label_max_value,
            'field_type': label_field_type
        })
    
    X_list = []
    is_dynamic_y = []
    min_size_y = []
    max_size_y = []
    min_value_y = []
    max_value_y = []
    field_type_y = []
    
    for d in training_data:
        X_list.append(create_feature_vector(d['features']))
        is_dynamic_y.append(d['is_dynamic_array'])
        min_size_y.append(d['min_size'])
        max_size_y.append(d['max_size'])
        min_value_y.append(d['min_value'])
        max_value_y.append(d['max_value'])
        field_type_y.append(d['field_type'])
    
    X = np.vstack(X_list)
    is_dynamic_y = np.array(is_dynamic_y)
    min_size_y = np.array(min_size_y, dtype=np.float32)
    max_size_y = np.array(max_size_y, dtype=np.float32)
    min_value_y = np.array(min_value_y, dtype=np.float32)
    max_value_y = np.array(max_value_y, dtype=np.float32)
    
    le_field_type = LabelEncoder()
    field_type_y_enc = le_field_type.fit_transform(field_type_y)
    
    input_dim = X.shape[1]
    epochs = 100
    batch_size = 8

    print("Training DPI subfield classifier for is_dynamic_array...")
    model_is_dynamic = build_classifier(input_dim, num_classes=2)
    history_is_dynamic = model_is_dynamic.fit(X, is_dynamic_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Is Dynamic Array Model Loss:", history_is_dynamic.history['loss'][-1],
          "Accuracy:", history_is_dynamic.history['accuracy'][-1])
    
    print("Training DPI subfield regressor models...")
    model_min_size = build_regressor(input_dim)
    history_min_size = model_min_size.fit(X, min_size_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Min Size Model Loss:", history_min_size.history['loss'][-1])
    
    model_max_size = build_regressor(input_dim)
    history_max_size = model_max_size.fit(X, max_size_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Max Size Model Loss:", history_max_size.history['loss'][-1])
    
    model_min_value = build_regressor(input_dim)
    history_min_value = model_min_value.fit(X, min_value_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Min Value Model Loss:", history_min_value.history['loss'][-1])
    
    model_max_value = build_regressor(input_dim)
    history_max_value = model_max_value.fit(X, max_value_y, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Max Value Model Loss:", history_max_value.history['loss'][-1])
    
    print("Training DPI subfield classifier model for field_type...")
    model_field_type = build_classifier(input_dim, num_classes=len(le_field_type.classes_))
    history_field_type = model_field_type.fit(X, field_type_y_enc, epochs=epochs, batch_size=batch_size, verbose=1)
    print("Field Type Model Loss:", history_field_type.history['loss'][-1],
          "Accuracy:", history_field_type.history['accuracy'][-1])
    
    # שמירת המודלים וה-encoder
    model_is_dynamic.save('dpi_model_is_dynamic_array.h5') #accuracy 93.8  loss 0.16
    model_min_size.save('dpi_model_min_size.h5') #mse 0.025
    model_max_size.save('dpi_model_max_size.h5') #mse 0.022
    model_min_value.save('dpi_model_min_value.h5') #mse 0.063
    model_max_value.save('dpi_model_max_value.h5') #mse 0.048
    model_field_type.save('dpi_model_field_type.h5') #accuracy 89.5  loss 0.34
    joblib.dump(le_field_type, 'dpi_label_encoder_field_type.joblib') 
    
    print("DPI subfield models trained and saved.")

##########################################
# פונקציית main
##########################################
def main():
    # if len(sys.argv) != 2:
    #     print("Usage: python train_dpi.py path_to_pcap_directory")
    #     sys.exit(1)
    pcap_directory = "/mnt/c/Users/aviv/Desktop/Final_Project/py_scripts/ML/data"
    if not os.path.exists(pcap_directory):
        print(f"PCAP directory '{pcap_directory}' does not exist.")
        sys.exit(1)
    train_dpi_subfield_models(pcap_directory)

if __name__ == '__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()