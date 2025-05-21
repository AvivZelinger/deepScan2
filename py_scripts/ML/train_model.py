#!/usr/bin/env python3
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

# ----------------------------------------
# Load custom types from MongoDB
# ----------------------------------------
def load_custom_types(mongo_uri: str, db_name: str, coll_name: str) -> dict:
    client = MongoClient(mongo_uri)
    coll = client[db_name][coll_name]
    result = {}
    for doc in coll.find():
        type_name = doc['name']
        total_size = int(doc.get('totalSize', 0))
        fields = []
        for f in doc.get('fields', []):
            fname = f['name']
            fsize = int(f['size'])
            ftype = f['type'].lower()
            if ftype == 'array':
                base = f['arrayType']
                ne = int(f['arrayCount'])
                fields.append({
                    'name': fname,
                    'size': fsize,
                    'type': f'array of {base}',
                    'size_field': '',
                    'num_elements': ne,
                    'is_bitfield': False
                })
            elif ftype in ('bitfield', 'bit'):
                fields.append({
                    'name': fname,
                    'size': fsize,
                    'type': 'bitfield',
                    'size_field': '',
                    'num_elements': 0,
                    'is_bitfield': True
                })
            else:
                fields.append({
                    'name': fname,
                    'size': fsize,
                    'type': ftype,
                    'size_field': '',
                    'num_elements': 0,
                    'is_bitfield': False
                })
        result[type_name] = {'fields': fields, 'total_size': total_size}
    return result

# ----------------------------------------
# Load protocol definitions from TXT
# ----------------------------------------
def load_protocol_definitions(file_path: str, custom_types: dict) -> pd.DataFrame:
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = [L.strip() for L in f if L.strip()]
    try:
        declared = int(lines[0])
    except ValueError:
        raise ValueError("The first line must be a valid field count.")
    rows = []
    for line in lines[1:]:
        toks = line.split()
        # custom type
        if len(toks) == 3 and toks[2] in custom_types:
            outer, sz, typ = toks
            for sub in custom_types[typ]['fields']:
                rows.append({
                    'name': f"{outer}.{sub['name']}",
                    'size': sub['size'],
                    'type': sub['type'],
                    'size_field': sub.get('size_field', ''),
                    'num_elements': sub.get('num_elements', 0),
                    'is_bitfield': sub['is_bitfield']
                })
            continue
        # array of custom type
        if len(toks) == 5 and toks[2].lower() == 'array' and toks[3] in custom_types:
            name, sz, _, base, ne = toks
            total, count = int(sz), int(ne)
            elem_size = custom_types[base]['total_size']
            if elem_size * count != total:
                print(f"Warning: {name} size mismatch: {total}!={elem_size}*{count}")
            for i in range(count):
                for sub in custom_types[base]['fields']:
                    rows.append({
                        'name': f"{name}[{i}].{sub['name']}",
                        'size': sub['size'],
                        'type': sub['type'],
                        'size_field': sub.get('size_field', ''),
                        'num_elements': sub.get('num_elements', 0),
                        'is_bitfield': sub['is_bitfield']
                    })
            continue
        # built-in array
        if len(toks) == 5 and toks[2].lower() == 'array':
            name, sz, _, base, ne = toks
            rows.append({
                'name': name,
                'size': int(sz),
                'type': f'array of {base}',
                'size_field': '',
                'num_elements': int(ne),
                'is_bitfield': False
            })
            continue
        # simple field
        if len(toks) == 3:
            name, sz, ftype = toks
            rows.append({
                'name': name,
                'size': int(sz),
                'type': ftype,
                'size_field': '',
                'num_elements': 0,
                'is_bitfield': ftype.lower() in ('bit', 'bitfield')
            })
            continue
        # dynamic with size_field
        if len(toks) == 4:
            name, sz, ftype, sf = toks
            rows.append({
                'name': name,
                'size': int(sz),
                'type': ftype,
                'size_field': sf,
                'num_elements': 0,
                'is_bitfield': ftype.lower() in ('bit', 'bitfield')
            })
            continue
        raise ValueError(f"Invalid line: {line}")
    if declared != len(rows):
        print(f"Warning: declared {declared} fields but found {len(rows)} rows.")
    return pd.DataFrame(rows)

# ----------------------------------------
# Parse PCAP and extract field records
# ----------------------------------------
def parse_pcap_with_ip(pcap_file: str, protocol_df: pd.DataFrame) -> dict:
    packets = rdpcap(pcap_file)
    data = defaultdict(list)
    packet_count = 1
    for pkt in packets:
        print(f"Processing packet {packet_count}")
        packet_count += 1
        if UDP in pkt and (pkt[UDP].dport == 10000 or pkt[UDP].sport == 10000):
            payload = bytes(pkt[UDP].payload)
            src = pkt[IP].src if pkt[UDP].dport == 10000 else pkt[IP].dst
            offset = 0
            records = []
            packet_data = {}
            for idx, row in protocol_df.iterrows():
                fname, fsize, ftype, sf, ne = (
                    row['name'], row['size'], row['type'], row['size_field'], int(row['num_elements'])
                )
                # dynamic size
                if fsize == 0:
                    remaining = sum(protocol_df.iloc[j]['size'] for j in range(idx+1, len(protocol_df)))
                    dyn = len(payload) - offset - remaining
                    if sf:
                        cand = packet_data.get(sf)
                        try: fsize = int(cand) if cand is not None else dyn
                        except: fsize = dyn
                    else:
                        fsize = dyn
                if offset + fsize > len(payload): break
                # array
                if ftype.startswith('array of '):
                    base = ftype.split('array of ', 1)[1]
                    elem_sz = fsize // ne
                    vals = []
                    for i in range(ne):
                        chunk = payload[offset + i*elem_sz: offset + (i+1)*elem_sz]
                        if base == 'int': vals.append(int.from_bytes(chunk,'big'))
                        elif base == 'float': vals.append(struct.unpack('!f',chunk)[0])
                        elif base == 'double': vals.append(struct.unpack('!d',chunk)[0])
                        elif base == 'char': vals.append(chunk.decode('utf-8','ignore').rstrip('\x00'))
                        else: vals.append(chunk.hex())
                    packet_data[fname] = vals
                    records.append({'field_name':fname,'size':fsize,'value':vals,'field_type':ftype,'num_elements':ne})
                    offset += fsize
                    continue
                # bitfield or primitive
                if row['is_bitfield']:
                    chunk = payload[offset:offset+fsize]
                    bits = list(map(int, format(int.from_bytes(chunk,'big'), f'0{fsize*8}b')))
                    val = bits; bcount = sum(bits)
                else:
                    chunk = payload[offset:offset+fsize]
                    lt = ftype.lower()
                    if lt == 'int': val = int.from_bytes(chunk,'big')
                    elif lt == 'float': val = struct.unpack('!f',chunk)[0]
                    elif lt == 'double': val = struct.unpack('!d',chunk)[0]
                    elif lt == 'char': val = chunk.decode('utf-8','ignore').rstrip('\x00')
                    elif lt == 'bool': val = bool(int.from_bytes(chunk,'big'))
                    else: val = chunk.hex()
                    bcount = None
                packet_data[fname] = val
                rec = {'field_name':fname,'size':fsize,'value':val,'field_type':ftype,'size_defining_field':sf,'bitfields_count':bcount}
                if row['is_bitfield']: rec['bit_vector'] = bits
                records.append(rec)
                offset += fsize
            if records: data[src].append(records)
    return data

# ----------------------------------------
# Feature extraction for DPI training
# ----------------------------------------
def extract_aggregated_features(stats: list) -> dict:
    sizes = np.array([s['size'] for s in stats], dtype=float)
    vals = []
    for s in stats:
        if isinstance(s['value'], list):
            for e in s['value']:
                try: vals.append(float(e))
                except: vals.append(0.0)
        else:
            try: vals.append(float(s['value']))
            except: vals.append(0.0)
    vals = np.array(vals, dtype=float) if vals else np.array([0.0])
    return {
        'count': len(sizes),
        'mean_size': float(np.mean(sizes)),
        'std_size': float(np.std(sizes)),
        'min_size': float(np.min(sizes)),
        'max_size': float(np.max(sizes)),
        'mean_value': float(np.mean(vals)),
        'std_value': float(np.std(vals)),
        'min_value': float(np.min(vals)),
        'max_value': float(np.max(vals)),
    }

def create_feature_vector(feats: dict) -> np.ndarray:
    return np.array([
        feats['count'], feats['mean_size'], feats['std_size'], feats['min_size'], feats['max_size'],
        feats['mean_value'], feats['std_value'], feats['min_value'], feats['max_value']
    ])

# ----------------------------------------
# Model builders
# ----------------------------------------
def build_regressor(input_dim: int):
    m = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.BatchNormalization(),
        layers.Dense(64, activation='relu', kernel_initializer='he_normal'),
        layers.Dropout(0.2),
        layers.BatchNormalization(),
        layers.Dense(32, activation='relu', kernel_initializer='he_normal'),
        layers.BatchNormalization(),
        layers.Dense(1, kernel_initializer='he_normal')
    ])
    m.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.001, clipnorm=1.0), 
              loss='huber')  # Using Huber loss for better stability
    return m

def build_classifier(input_dim: int, num_classes: int):
    m = models.Sequential([
        layers.Input(shape=(input_dim,)),
        layers.BatchNormalization(),
        layers.Dense(128, activation='relu', kernel_initializer='he_normal'),
        layers.Dropout(0.3),
        layers.BatchNormalization(),
        layers.Dense(64, activation='relu', kernel_initializer='he_normal'),
        layers.Dropout(0.3),
        layers.BatchNormalization(),
        layers.Dense(32, activation='relu', kernel_initializer='he_normal'),
        layers.BatchNormalization(),
        layers.Dense(num_classes, activation='softmax', kernel_initializer='he_normal')
    ])
    m.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=0.0005, clipnorm=0.5),
              loss='sparse_categorical_crossentropy',
              metrics=['accuracy'])
    return m

# ----------------------------------------
# Training DPI subfield models (including bit count)
# ----------------------------------------
def train_dpi_subfield_models(pcap_directory: str):
    pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory)
                  if f.endswith('.pcap') or f.endswith('.pcapng')]
    if not pcap_files:
        print(f"No PCAP files in {pcap_directory}"); sys.exit(1)
    agg_eps = defaultdict(list)
    custom_types = load_custom_types('mongodb://localhost:27017/', 'custom_types_db', 'customtypes')
    protocol_df = load_protocol_definitions('/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/train.txt', custom_types)
    for f in pcap_files:
        print(f)
        for ip, pkts in parse_pcap_with_ip(f, protocol_df).items(): agg_eps[ip].extend(pkts)
    # aggregate stats
    all_stats = defaultdict(list)
    for pkts in agg_eps.values():
        for p in pkts:
            for fld in p: all_stats[fld['field_name']].append(fld)

    # prepare training data
    X_list, y_dyn, y_min_sz, y_max_sz, y_min_val, y_max_val, y_ft, y_bit = [], [], [], [], [], [], [], []
    for name, stats in all_stats.items():
        feats = extract_aggregated_features(stats)
        vec = create_feature_vector(feats)
        sizes = [s['size'] for s in stats]
        # dynamic label
        proto = protocol_df[protocol_df['name']==name]
        dyn = 1 if (not proto.empty and proto.iloc[0]['size_field']) else (1 if len(set(sizes))>1 else 0)
        # min/max sizes
        mn_sz, mx_sz = min(sizes), max(sizes)
        # values
        vals = []
        for s in stats:
            try:
                if s['field_type'].lower() in ('int','float','double','long','short'):
                    vals.append(float(s['value']))
            except: pass
        if not vals: vals=[0.0]
        mn_val, mx_val = min(vals), max(vals)
        # field type
        ft_series = pd.Series([s['field_type'] for s in stats if s.get('field_type')])
        ft_lbl = ft_series.mode()[0] if not ft_series.empty else 'unknown'
        # bit count
        if ft_lbl.lower()=='bitfield':
            bc = [sum(s['value']) for s in stats if isinstance(s['value'], list)]
            bit = int(round(np.mean(bc))) if bc else 0
        else:
            bit = 0
        # append
        X_list.append(vec)
        y_dyn.append(dyn); y_min_sz.append(mn_sz); y_max_sz.append(mx_sz)
        y_min_val.append(mn_val); y_max_val.append(mx_val)
        y_ft.append(ft_lbl); y_bit.append(bit)

    X = np.vstack(X_list)
    # Normalize input features with robust scaling
    X = (X - np.median(X, axis=0)) / (np.percentile(X, 75, axis=0) - np.percentile(X, 25, axis=0) + 1e-8)
    
    # Print information about X
    print("\nX shape:", X.shape)
    print("X statistics after normalization:")
    print("Mean:", np.mean(X, axis=0))
    print("Std:", np.std(X, axis=0))
    print("Min:", np.min(X, axis=0))
    print("Max:", np.max(X, axis=0))
    print("Median:", np.median(X, axis=0))
    print(X)
    
    y_dyn = np.array(y_dyn); y_min_sz = np.array(y_min_sz); y_max_sz = np.array(y_max_sz)
    y_min_val = np.array(y_min_val); y_max_val = np.array(y_max_val); y_bit = np.array(y_bit)
    # encode field types
    le = LabelEncoder(); y_ft_enc = le.fit_transform(y_ft)

    dim = X.shape[1]; ep=50; bs=16  # Increased batch size
    # train models with early stopping
    early_stopping = tf.keras.callbacks.EarlyStopping(
        monitor='loss',
        patience=10,
        restore_best_weights=True
    )
    
    # train models
    print("Training models...")
    print("Training is_dynamic_array model...")
    mdyn = build_classifier(dim,2); mdyn.fit(X,y_dyn,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training min_size model...")
    mminsz = build_regressor(dim); mminsz.fit(X,y_min_sz,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training max_size model...")
    mmaxsz = build_regressor(dim); mmaxsz.fit(X,y_max_sz,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training min_value model...")
    mminv = build_regressor(dim); mminv.fit(X,y_min_val,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training max_value model...")
    mmaxv = build_regressor(dim); mmaxv.fit(X,y_max_val,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training field_type model...")
    mft = build_classifier(dim,len(le.classes_)); mft.fit(X,y_ft_enc,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])
    
    print("Training bit_count model...")
    mbit = build_regressor(dim); mbit.fit(X,y_bit,epochs=ep,batch_size=bs,verbose=1,callbacks=[early_stopping])

    print("Training complete.")
    print("models mse and accuracy:")
    print(f"is_dynamic_array: {mdyn.evaluate(X, y_dyn)}")
    print(f"min_size: {mminsz.evaluate(X, y_min_sz)}")
    print(f"max_size: {mmaxsz.evaluate(X, y_max_sz)}")
    print(f"min_value: {mminv.evaluate(X, y_min_val)}")
    print(f"max_value: {mmaxv.evaluate(X, y_max_val)}")
    print(f"field_type: {mft.evaluate(X, y_ft_enc)}")
    print(f"bit_count: {mbit.evaluate(X, y_bit)}")

    # save
    mdyn.save('dpi_model_is_dynamic_array.h5')
    mminsz.save('dpi_model_min_size.h5')
    mmaxsz.save('dpi_model_max_size.h5')
    mminv.save('dpi_model_min_value.h5')
    mmaxv.save('dpi_model_max_value.h5')
    mft.save('dpi_model_field_type.h5')
    mbit.save('dpi_model_bit_count.h5')
    joblib.dump(le,'dpi_label_encoder_field_type.joblib')
    print("DPI subfield models (including bit count) trained and saved.")

# ----------------------------------------
# Main execution
# ----------------------------------------
def main():
    # if len(sys.argv)!=2:
    #     print("Usage: python train_dpi.py <pcap_directory>"); sys.exit(1)
    dir = '/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/py_scripts/ML/data2'
    if not os.path.isdir(dir):
        print(f"Directory '{dir}' not found."); sys.exit(1)
    train_dpi_subfield_models(dir)

if __name__=='__main__':
    os.environ['TF_CPP_MIN_LOG_LEVEL']='3'
    tf.get_logger().setLevel('ERROR')
    warnings.filterwarnings('ignore')
    main()
