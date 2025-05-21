#!/usr/bin/env python3
"""
This script reads a DPI JSON file that describes the protocol fields for each IP and percentage,
and generates:
  1. A Wireshark Lua dissector file per IP and per percentage that decodes each field and runs DPI tests.
     - If no errors, the Info column shows the parsed field values.
     - If errors, the Info column only shows "[DPI Error: ...]".
  2. A general static dissector (saved as <protocol>.lua) that decodes fields by fixed sizes (no DPI tests),
     showing a summary of fields in the Info column.

Now with full support for fixed-length arrays of the form "array of TYPE". Each element becomes its own ProtoField,
with per-element bounds checking based on the corresponding entries in the JSON arrays.
"""

import json
import os
from pymongo import MongoClient

# --- MongoDB Setup ---
# Adjust the connection string, database, and collection names as needed.
client = MongoClient("mongodb://localhost:27017/")
db = client["lua_dissectors_db"]
collection = db["dissectors"]

# Path to the DPI JSON file (change as needed)
JSON_FILENAME = "/mnt/c/Users/aviv/Desktop/FinalProject_obj,array,bitfield/server/dpi_output.json"

# Load the DPI specification
with open(JSON_FILENAME, "r") as f:
    dpi_spec = json.load(f)

protocol = dpi_spec.get("protocol", "CustomProtocol")
dpi_data = dpi_spec.get("dpi", {})

##########################################################################
# Helper function to split object fields
##########################################################################

def split_object_fields(fields):
    """
    Splits keys like "obj.field" into object_fields[obj][field] = info,
    and everything else into simple_fields.
    """
    simple_fields = {}
    object_fields = {}
    for fname, info in fields.items():
        if "." in fname:
            obj, subf = fname.split(".", 1)
            object_fields.setdefault(obj, {})[subf] = info
        else:
            simple_fields[fname] = info
    return simple_fields, object_fields


##########################################################################
# Helper function to generate the list of all fields (including bitfields and arrays)
##########################################################################
def generate_field_list(fields):
    simple_fields, object_fields = split_object_fields(fields)
    all_fields = []

    # 1) one entry per object group + its sub-fields
    for obj, subdict in object_fields.items():
        # the group itself
        all_fields.append(f"f_{obj}")
        # then each sub-field (array or scalar)
        for subf, info in subdict.items():
            ftype = info.get("field_type", "")
            if ftype.startswith("array of"):
                all_fields.append(f"f_{obj}_{subf}")
                for i in range(len(info.get("min_size", []))):
                    all_fields.append(f"f_{obj}_{subf}_{i}")
            else:
                all_fields.append(f"f_{obj}_{subf}")
                for i in range(info.get("bitfields_count") or 0):

                    all_fields.append(f"f_{obj}_{subf}_bf{i}")

    # 2) then top-level (non-object) fields exactly as before
    for field_name, info in simple_fields.items():
        ftype = info.get("field_type", "")
        safe_name = field_name.replace(".", "_")

        if ftype.startswith("array of"):
            all_fields.append(f"f_{safe_name}")
            for i in range(len(info.get("min_size", []))):
                all_fields.append(f"f_{safe_name}_{i}")
        else:
            all_fields.append(f"f_{safe_name}")
            for i in range(info.get("bitfields_count") or 0):

                all_fields.append(f"f_{safe_name}_bf{i}")

    return all_fields


##########################################################################
# 1. Generate per-IP and per-Percentage Lua dissectors (with DPI tests)
##########################################################################
for ip, percent_data in dpi_data.items():
    for percentage, fields in percent_data.items():
        ip_clean = ip.replace('.', '_')
        percentage_clean = percentage.replace('%', 'pct')
        proto_name = f"{protocol}_{ip_clean}_{percentage_clean}"
        filename = f"{protocol}_for_{ip_clean}_{percentage_clean}.lua"

        content_lines = []
        # Header
        content_lines.append(f"-- Wireshark Lua dissector for {protocol} on IP {ip} at {percentage}")
        content_lines.append("-- Generated automatically from DPI JSON.\n")

        # Proto definition
        content_lines.append(f"local {proto_name} = Proto(\"{proto_name}\", \"{protocol} for IP {ip} at {percentage}\")\n")

        # --- Part 3: Replace your existing “Declare ProtoFields” block with this entire snippet ---

        simple_fields, object_fields = split_object_fields(fields)

        # 1) Declare a collapsible “group” field for each object
        for obj in object_fields:
            content_lines.append(
                f"local f_{obj} = ProtoField.none(\"{proto_name}.{obj}\", \"{obj}\")"
            )

        # 2) Declare all top-level (simple) fields exactly as before
        for field_name, info in simple_fields.items():
            ftype = info["field_type"]
            safe_name = field_name.replace(".", "_")
            # --- fixed‑array support ---
            if ftype.startswith("array of"):
                elem_type = ftype[len("array of"):].strip()
                sizes     = info.get("min_size", [])
                count     = len(sizes)

                # parent field
                if elem_type == "char":
                    content_lines.append(
                        f"local f_{safe_name} = ProtoField.string("
                        f"\"{proto_name}.{safe_name}\", \"{safe_name}\")"
                    )
                else:
                    content_lines.append(
                        f"local f_{safe_name} = ProtoField.bytes("
                        f"\"{proto_name}.{safe_name}\", \"{safe_name}\")"
                    )

                # per‑element fields
                for i in range(count):
                    size_i = int(sizes[i])
                    if elem_type in ["short", "int"]:
                        if size_i == 1:   pftype = "ProtoField.uint8"
                        elif size_i == 2: pftype = "ProtoField.uint16"
                        elif size_i == 4: pftype = "ProtoField.uint32"
                        else:             pftype = "ProtoField.uint32"
                        base = ", base.DEC"
                    elif elem_type == "float":
                        pftype, base = "ProtoField.float", ""
                    elif elem_type == "double":
                        pftype, base = "ProtoField.double", ""
                    else:
                        pftype, base = "ProtoField.string", ""
                    content_lines.append(
                        f"local f_{safe_name}_{i} = {pftype}(\"{proto_name}.{safe_name}_{i}\", "
                        f"\"{safe_name}[{i}]\"){base}"
                    )
                continue
            # --- end array support ---

            # --- scalar & bitfield declarations ---
            if ftype == "bool":
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.uint8(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                )
            elif ftype == "int":
                size = info["min_size"]
                if size == 1:
                    pf = "ProtoField.uint8"
                elif size == 2:
                    pf = "ProtoField.uint16"
                elif size == 4:
                    pf = "ProtoField.uint32"
                elif size == 8:
                    pf = "ProtoField.uint64"
                else:
                    pf = "ProtoField.uint32"
                content_lines.append(
                    f"local f_{safe_name} = {pf}(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                )
            elif ftype == "float":
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.float(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\")"
                )
            elif ftype == "double":
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.double(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\")"
                )
            elif ftype == "long":
                if info["min_size"] == 8:
                    content_lines.append(
                        f"local f_{safe_name} = ProtoField.uint64(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                    )
                else:
                    content_lines.append(
                        f"local f_{safe_name} = ProtoField.int32(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                    )
            elif ftype == "char":
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.string(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\")"
                )
            elif ftype == "bitfield":
                sz = info["min_size"]
                if sz == 1:
                    pf = "ProtoField.uint8"
                elif sz == 2:
                    pf = "ProtoField.uint16"
                elif sz == 4:
                    pf = "ProtoField.uint32"
                elif sz == 8:
                    pf = "ProtoField.uint64"
                else:
                    pf = "ProtoField.uint32"
                content_lines.append(
                    f"local f_{safe_name} = {pf}(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()} (Bitfield)\")"
                )
            else:
                # fallback to string
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.string(\"{proto_name}.{safe_name}\", \"{safe_name.capitalize()}\")"
                )

        # 3) Declare each object’s sub-fields under its group
        for obj, subdict in object_fields.items():
            for subf, info in subdict.items():
                ftype = info["field_type"]

                # --- object array support ---
                if ftype.startswith("array of"):
                    elem_type = ftype[len("array of"):].strip()
                    sizes     = info.get("min_size", [])
                    count     = len(sizes)

                    # parent
                    if elem_type == "char":
                        content_lines.append(
                            f"local f_{obj}_{subf} = ProtoField.string(\"{proto_name}.{obj}.{subf}\", \"{subf}\")"
                        )
                    else:
                        content_lines.append(
                            f"local f_{obj}_{subf} = ProtoField.bytes(\"{proto_name}.{obj}.{subf}\", \"{subf}\")"
                        )

                    # elements
                    for i in range(count):
                        size_i = int(sizes[i])
                        if elem_type in ["short", "int"]:
                            if size_i == 1:   pftype = "ProtoField.uint8"
                            elif size_i == 2: pftype = "ProtoField.uint16"
                            elif size_i == 4: pftype = "ProtoField.uint32"
                            else:             pftype = "ProtoField.uint32"
                            base = ", base.DEC"
                        elif elem_type == "float":
                            pftype, base = "ProtoField.float", ""
                        elif elem_type == "double":
                            pftype, base = "ProtoField.double", ""
                        else:
                            pftype, base = "ProtoField.string", ""
                        content_lines.append(
                          # f"local f_{obj}_{subf}_{i} = {pftype}(\"{proto_name}.{obj}.{subf}[{i}]\", \"{subf}[{i}]\"){base}"
                            f"local f_{obj}_{subf}_{i} = {pftype}(\"{proto_name}.{obj}.{subf}_{i}\", \"{subf}[{i}]\"){base}"

                        )
                    continue
                # --- end object array support ---

                # --- object scalar & bitfield ---
                if info["field_type"] == "bool":
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.uint8(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                    )
                elif info["field_type"] == "int":
                    size = info["min_size"]
                    if size == 1:
                        pf = "ProtoField.uint8"
                    elif size == 2:
                        pf = "ProtoField.uint16"
                    elif size == 4:
                        pf = "ProtoField.uint32"
                    elif size == 8:
                        pf = "ProtoField.uint64"
                    else:
                        pf = "ProtoField.uint32"
                    content_lines.append(
                        f"local f_{obj}_{subf} = {pf}(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                    )
                elif info["field_type"] == "float":
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.float(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                    )
                elif info["field_type"] == "double":
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.double(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                    )
                elif info["field_type"] == "long":
                    if info["min_size"] == 8:
                        content_lines.append(
                            f"local f_{obj}_{subf} = ProtoField.uint64(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                        )
                    else:
                        content_lines.append(
                            f"local f_{obj}_{subf} = ProtoField.int32(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                        )
                elif info["field_type"] == "char":
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.string(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                    )
                elif info["field_type"] == "bitfield":
                    sz = info["min_size"]
                    if sz == 1:
                        pf = "ProtoField.uint8"
                    elif sz == 2:
                        pf = "ProtoField.uint16"
                    elif sz == 4:
                        pf = "ProtoField.uint32"
                    elif sz == 8:
                        pf = "ProtoField.uint64"
                    else:
                        pf = "ProtoField.uint32"
                    content_lines.append(
                        f"local f_{obj}_{subf} = {pf}(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()} (Bitfield)\")"
                    )
                else:
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.string(\"{proto_name}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                    )

                # any bitfield sub‑fields
                bf_cnt = info.get("bitfields_count") or 0
                for i in range(bf_cnt):
                    lbl = f"{subf.capitalize()} Bitfield {i+1}"
                    content_lines.append(
                        f"local f_{obj}_{subf}_bf{i} = ProtoField.uint8(\"{proto_name}.{obj}.{subf}_bf{i}\", \"{lbl}\", base.DEC)"
                    )
                if bf_cnt:
                    lst = ", ".join(f"f_{obj}_{subf}_bf{i}" for i in range(bf_cnt))
                    content_lines.append(f"local bf_fields_{obj}_{subf} = {{ {lst} }}")

        # blank line and register all fields
        content_lines.append("\n")
        all_fields = generate_field_list(fields)
        content_lines.append(f"{proto_name}.fields = {{ {', '.join(all_fields)} }}\n")

        # Continue with Part 4 and the rest… (omitted for brevity)


            # Begin dissector function and add helper functions for bitfield processing
        content_lines.append(f"function {proto_name}.dissector(buffer, pinfo, tree)")
        content_lines.append("    if buffer:len() == 0 then return end")
        content_lines.append(f"    pinfo.cols.protocol = \"{protocol}\"")
        content_lines.append(
            f"    local subtree = tree:add({proto_name}, buffer(), "
            f"\"{protocol} for IP {ip} at {percentage}\")"
        )
        content_lines.append("    local offset = 0")
        content_lines.append("    local dpi_error     = false")
        content_lines.append("    local error_messages = {}")
        content_lines.append("    local parsed_values  = {}")


        content_lines.append("    -- Helper function to count the number of bits set in a value")
        content_lines.append("    local function popcount(x)")
        content_lines.append("        local count = 0")
        content_lines.append("        while x > 0 do")
        content_lines.append("            count = count + (x % 2)")
        content_lines.append("            x = math.floor(x / 2)")
        content_lines.append("        end")
        content_lines.append("        return count")
        content_lines.append("    end\n")
        content_lines.append("    -- Helper function to convert a number to a binary string of a given bit length")
        content_lines.append("    local function to_binary_str(num, bits)")
        content_lines.append("        local s = \"\"")
        content_lines.append("        for i = bits - 1, 0, -1 do")
        content_lines.append("            local bit_val = bit.rshift(num, i)")
        content_lines.append("            s = s .. (bit.band(bit_val, 1) == 1 and \"1\" or \"0\")")
        content_lines.append("        end")
        content_lines.append("        return s")
        content_lines.append("    end\n")

                # 4) Insert the following **immediately after** these two lines in your per-IP dissector:
        #
        #     content_lines.append(f"    local subtree = tree:add({proto_name}, buffer(), \"{protocol} for IP {ip} at {percentage}\")")
        #     content_lines.append("    local offset = 0")
        #
        # Copy-and-paste this block right below them:
        # --- Begin object-group parsing ---
        content_lines.append("    -- Object groups (dotted fields)")
        for obj in object_fields:
            # add the group node
            content_lines.append(f"    local {obj}_tree = subtree:add(f_{obj}, buffer())")
            # for each field under this object
            for subf, info in object_fields[obj].items():
                ftype = info.get("field_type", "")
                if ftype == "bitfield":
                    size = info["min_size"]
                    cnt  = info["bitfields_count"]
                    content_lines.append(f"    -- Bitfield field: {obj}.{subf}")
                    content_lines.append(f"    if buffer:len() < offset + {size} then")
                    content_lines.append(
                        f"        {obj}_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Not enough bytes for {subf}\")"
                    )
                    content_lines.append("    else")
                    if size == 8:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint64()")
                    else:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint()")
                    content_lines.append(
                        f"        local item = {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {size}))"
                    )
                    content_lines.append("        local actual = popcount(val)")
                    content_lines.append(f"        if actual ~= {cnt} then")
                    content_lines.append(
                        f"            item:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Bitfield {subf} expected {cnt} bits set, got \"..actual)"
                    )
                    content_lines.append("            dpi_error = true")
                    content_lines.append(
                        f"            table.insert(error_messages, "
                        f"\"{obj}.{subf} bitfield expected {cnt} bits set, got \"..actual)"
                    )
                    content_lines.append("        end")

                    content_lines.append(
                        f"        item:append_text(\" (\"..to_binary_str(val, {size}*8)..\")\")"
                    )
                    content_lines.append(f"        offset = offset + {size}")
                    content_lines.append("    end")
                # ---- array handling ----
                elif ftype.startswith("array of"):
                    sizes    = info.get("min_size", [])
                    total_len = sum(int(s) for s in sizes)
                    content_lines.append(f"    -- Array field: {obj}.{subf}")
                    content_lines.append(f"    if buffer:len() < offset + {total_len} then")
                    content_lines.append(f"        {obj}_tree:add_expert_info(PI_MALFORMED, PI_ERROR, \"Not enough bytes for array {obj}.{subf}\")")
                    content_lines.append("    else")
                    content_lines.append(f"        local arr_tree = {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {total_len}))")
                    content_lines.append("        local elt_off = 0")
                    for i, sz in enumerate(sizes):
                        content_lines.append(f"        arr_tree:add(f_{obj}_{subf}_{i}, buffer(offset + elt_off, {int(sz)}))")
                        content_lines.append(f"        elt_off = elt_off + {int(sz)}")
                    content_lines.append(f"        offset = offset + {total_len}")
                    content_lines.append("    end")
                
                # ---- scalar/bitfield handling ----
                else:
                    size = int(info.get("min_size", 0))
                    content_lines.append(f"    -- Scalar field: {obj}.{subf}")
                    content_lines.append(f"    {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {size}))")
                    content_lines.append(f"    offset = offset + {size}")
        # --- End object-group parsing ---
       
        # Helper functions for bitfield type

        # Parse each field (with array support)
        for field_name, info in simple_fields.items():
            ftype = info["field_type"]
            safe_name = field_name.replace(".", "_")
            # ----- array parsing support -----
            if ftype.startswith("array of"):
                sizes    = info.get("min_size", [])
                total_len = sum(int(s) for s in sizes)
                content_lines.append(f"    -- Array: {safe_name}")
                content_lines.append(f"    if buffer:len() < offset + {total_len} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for array {safe_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append("        return")
                content_lines.append("    end\n")
                # parent covers entire slice
                content_lines.append(
                        f"    local arr_tree = subtree:add(f_{safe_name}, buffer(offset, {total_len}))"
                )
                content_lines.append("    local elt_off = 0")
                for i in range(len(sizes)):
                    size_i = int(sizes[i])
                    content_lines.append(
                        f"    arr_tree:add(f_{safe_name}_{i}, buffer(offset + elt_off, {size_i}))"
                    )
                    content_lines.append(f"    elt_off = elt_off + {size_i}")
                content_lines.append(f"    offset = offset + {total_len}\n")
                continue
            # ----- end array parsing support -----
            # existing bitfield, scalar, and dynamic array branches...
            if ftype == "bitfield":
                # (original bitfield parsing code here)
                content_lines.append(f"    -- Field: {safe_name}")
                content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {safe_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(f"        table.insert(error_messages, \"Not enough bytes for {safe_name}\")")
                content_lines.append("        return")
                content_lines.append("    end")
                if info["min_size"] == 8:
                    content_lines.append(
                        f"    local {safe_name} = buffer(offset, {info['min_size']}):uint64()"
                    )
                else:
                    content_lines.append(
                        f"    local {safe_name} = buffer(offset, {info['min_size']}):uint()"
                    )
                content_lines.append(
                    f"    local {safe_name}_item = subtree:add(f_{safe_name}, buffer(offset, {info['min_size']}))"
                )
                content_lines.append(f"    local num_bits = {info['min_size']} * 8")
                content_lines.append(f"    local actual_bit_count = popcount({safe_name})")
                content_lines.append(
                    f"    if actual_bit_count ~= {info['bitfields_count']} then"
                )
                content_lines.append(
                    f"        {safe_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, "
                            f"\"Bitfield {safe_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, "
                    f"\"Bitfield {safe_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)"
                )
                content_lines.append("    end")
                content_lines.append(
                    f"    local binary_str = to_binary_str({safe_name}, num_bits)"
                )
                content_lines.append(
                    f"    {safe_name}_item:append_text(\" (\" .. binary_str .. \")\")"
                )
                content_lines.append(f"    parsed_values['{safe_name}'] = binary_str")
                content_lines.append(f"    offset = offset + {info['min_size']}\n")
            elif not info.get("is_dynamic_array", False):
                # (original scalar parsing code here including range checks and bitfield slices)
                content_lines.append(f"    -- Field: {safe_name}")
                content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {safe_name}\")"
                )
                content_lines.append("        return")
                content_lines.append("    end")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        content_lines.append(
                            f"    local {safe_name} = buffer(offset, {info['min_size']}):uint64()"
                        )
                    else:
                        content_lines.append(
                            f"    local {safe_name} = buffer(offset, {info['min_size']}):uint()"
                        )
                elif ftype == "float":
                    content_lines.append(
                        f"    local {safe_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {safe_name} = string.unpack(\">f\", {safe_name}_bytes)"
                    )
                elif ftype == "double":
                    content_lines.append(
                        f"    local {safe_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {safe_name} = string.unpack(\">d\", {safe_name}_bytes)"
                    )
                else:
                    content_lines.append(
                        f"    local {safe_name} = buffer(offset, {info['min_size']}):string()"
                    )
                content_lines.append(
                    f"    local {safe_name}_item = subtree:add(f_{safe_name}, buffer(offset, {info['min_size']}))"
                )
                content_lines.append(f"    parsed_values['{safe_name}'] = {safe_name}")
                if ftype in ["int", "bool", "long", "float", "double"] and \
                info.get("min_value") is not None and info.get("max_value") is not None:
                    content_lines.append("    do")
                    content_lines.append(f"        local min_val = {info['min_value']}")
                    content_lines.append(f"        local max_val = {info['max_value']}")
                    content_lines.append(
                        f"        if {safe_name} < min_val or {safe_name} > max_val then"
                    )
                    content_lines.append(
                        f"            {safe_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Value out of range for {safe_name}\")"
                    )
                    content_lines.append("            dpi_error = true")
                    content_lines.append(
                        f"            table.insert(error_messages, \"{safe_name} out of range\")"
                    )
                    content_lines.append("        end")
                    content_lines.append("    end")
                content_lines.append(f"    offset = offset + {info['min_size']}\n")
                # per-scalar bitfield slicing
                bf_count = info.get("bitfields_count") or 0
                if bf_count:
                    content_lines.append("    do")
                    content_lines.append(
                        f"        local bits_per_field = ({info['min_size']} * 8) / {bf_count}"
                    )
                    content_lines.append(
                        f"        for i = 0, {bf_count} - 1 do"
                    )
                    content_lines.append(
                        "            local shift = (({0} - 1 - i) * bits_per_field)".format(bf_count)
                    )
                    content_lines.append(
                        "            local mask = (1 << bits_per_field) - 1"
                    )
                    content_lines.append(
                        f"            local bf_value = bit.band(bit.rshift({safe_name}, shift), mask)"
                    )
                    content_lines.append(
                        f"            subtree:add(bf_fields_{safe_name}[i+1], bf_value)"
                    )
                    content_lines.append(
                        f"            parsed_values['{safe_name}_bf' .. i] = bf_value"
                    )
                    content_lines.append("        end")
                    content_lines.append("    end\n")
            else:
                # dynamic array parsing (unchanged)
                size_field = info["size_defining_field"]
                content_lines.append(f"    -- Dynamic array: {safe_name}")
                content_lines.append(f"    local dynamic_length = {size_field}")
                content_lines.append(
                    f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then"
                )
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"{safe_name} length out of range\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, \"{safe_name} length out of range\")"
                )
                content_lines.append("    end")
                content_lines.append(
                    f"    if buffer:len() < offset + dynamic_length then"
                )
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {safe_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, \"Not enough bytes for {safe_name}\")"
                )
                content_lines.append("        return")
                content_lines.append("    end")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        content_lines.append(
                            f"    local {safe_name} = buffer(offset, dynamic_length):uint64()"
                        )
                    else:
                        content_lines.append(
                            f"    local {safe_name} = buffer(offset, dynamic_length):uint()"
                        )
                elif ftype == "float":
                    content_lines.append(
                        f"    local {safe_name}_bytes = buffer(offset, dynamic_length):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {safe_name} = string.unpack(\">f\", {safe_name}_bytes)"
                    )
                elif ftype == "double":
                    content_lines.append(
                        f"    local {safe_name}_bytes = buffer(offset, dynamic_length):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {safe_name} = string.unpack(\">d\", {safe_name}_bytes)"
                    )
                else:
                    content_lines.append(
                        f"    local {safe_name} = buffer(offset, dynamic_length):string()"
                    )
                content_lines.append(
                    f"    local {safe_name}_item = subtree:add(f_{safe_name}, buffer(offset, dynamic_length))"
                )
                content_lines.append(f"    parsed_values['{safe_name}'] = {safe_name}")
                content_lines.append("    offset = offset + dynamic_length\n")
                bf_count = info.get("bitfields_count") or 0
                if bf_count:
                    content_lines.append("    do")
                    content_lines.append(
                        f"        local bits_per_field = (dynamic_length * 8) / {bf_count}"
                    )
                    content_lines.append(
                        f"        for i = 0, {bf_count} - 1 do"
                    )
                    content_lines.append(
                        "            local shift = (({0} - 1 - i) * bits_per_field)".format(bf_count)
                    )
                    content_lines.append(
                        "            local mask = (1 << bits_per_field) - 1"
                    )
                    content_lines.append(
                        f"            local bf_value = bit.band(bit.rshift({safe_name}, shift), mask)"
                    )
                    content_lines.append(
                        f"            subtree:add(bf_fields_{safe_name}[i+1], bf_value)"
                    )
                    content_lines.append(
                        f"            parsed_values['{safe_name}_bf' .. i] = bf_value"
                    )
                    content_lines.append("        end")
                    content_lines.append("    end\n")

        # Print packet details for debugging
        content_lines.append("    -- Print packet details for each field (for debugging purposes)")
        content_lines.append(f"    print(\"Packet details for IP {ip} at {percentage}:\")")
        content_lines.append("    for k, v in pairs(parsed_values) do")
        content_lines.append("        print(\"  \" .. k .. \" = \" .. tostring(v))")
        content_lines.append("    end\n")

        content_lines.append("    if dpi_error then")
        content_lines.append("        local msg = table.concat(error_messages, \"; \")")
        content_lines.append("        pinfo.cols.info = \"[DPI Error: \" .. msg .. \"]\"")
        content_lines.append("        subtree:add_expert_info(PI_PROTOCOL, PI_ERROR, \"DPI Error in this packet\")")
        content_lines.append("    else")
        content_lines.append("        local parts = {}")
        content_lines.append("        for k, v in pairs(parsed_values) do")
        content_lines.append("            table.insert(parts, k .. \"=\" .. tostring(v))")
        content_lines.append("        end")
        content_lines.append("        table.sort(parts)")
        content_lines.append("        pinfo.cols.info = table.concat(parts, \", \")")
        content_lines.append("    end")
        content_lines.append("end\n")

        content_lines.append("-- Register this dissector for UDP port")
        content_lines.append("local udp_port = DissectorTable.get(\"udp.port\")")
        content_lines.append(f"udp_port:add(10000, {proto_name})")

        # Insert into MongoDB
        document = {"filename": filename, "content": "\n".join(content_lines)}
        collection.insert_one(document)
        print(f"Inserted per-IP dissector document: {filename}")

##########################################################################
# 2. Generate a single static general dissector (no DPI tests) as <protocol>.lua
##########################################################################
if dpi_data:
    first_ip        = next(iter(dpi_data))
    first_percentage = next(iter(dpi_data[first_ip]))
    fields          = dpi_data[first_ip][first_percentage]
    static_filename = f"{protocol}.lua"

    content_lines = []
    content_lines.append(f"-- Wireshark Lua static dissector for {protocol}")
    content_lines.append(
        f"-- Decodes fields by fixed sizes (no DPI tests) using fields from IP "
        f"{first_ip} at {first_percentage}\n"
    )

    # Proto definition
    content_lines.append(f"local {protocol} = Proto(\"{protocol}\", \"{protocol}\")\n")
# --- Part 5: STATIC DISSECTOR – Declare ProtoFields and parse object groups ---

# Insert this **instead** of your original “Declare ProtoFields” loop in the static section:

    # 1) Split fields
    simple_fields, object_fields = split_object_fields(fields)

    # 2) Declare a ProtoField.none for each object group
    for obj in object_fields:
        content_lines.append(
            f"local f_{obj} = ProtoField.none(\"{protocol}.{obj}\", \"{obj}\")"
        )

    # 3) Top-level (simple) fields exactly as before
    for field_name, info in simple_fields.items():
        ftype = info["field_type"]
        safe_name = field_name.replace(".", "_")    
        
        # ---- fixed-array support ----
        if ftype.startswith("array of"):
            elem_type = ftype[len("array of"):].strip()
            sizes     = info.get("min_size", [])
            count     = len(sizes)

            # parent field
            if elem_type == "char":
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.string("     
                    f"\"{protocol}.{safe_name}\", \"{safe_name}\")"
                )
            else:
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.bytes("
                    f"\"{protocol}.{safe_name}\", \"{safe_name}\")"
                )

            # per-element fields
            for i in range(count):
                size_i = int(sizes[i])
                if elem_type in ["short", "int"]:
                    if   size_i == 1: pftype = "ProtoField.uint8"
                    elif size_i == 2: pftype = "ProtoField.uint16"
                    elif size_i == 4: pftype = "ProtoField.uint32"
                    else:             pftype = "ProtoField.uint32"
                    base = ", base.DEC"
                elif elem_type == "float":
                    pftype, base = "ProtoField.float", ""
                elif elem_type == "double":
                    pftype, base = "ProtoField.double", ""
                else:
                    pftype, base = "ProtoField.string", ""
                content_lines.append(
                    f"local f_{safe_name}_{i} = {pftype}(\"{protocol}.{safe_name}_{i}\", "
                    f"\"{safe_name}[{i}]\"){base}"
                )
            continue
        # ---- end array support ----

        # ---- scalar & bitfield declarations ----
        if ftype == "bool":
            content_lines.append(
                f"local f_{safe_name} = ProtoField.uint8("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
            )
        elif ftype == "int":
            sz = info["min_size"]
            if   sz == 1: pf = "ProtoField.uint8"
            elif sz == 2: pf = "ProtoField.uint16"
            elif sz == 4: pf = "ProtoField.uint32"
            elif sz == 8: pf = "ProtoField.uint64"
            else:         pf = "ProtoField.uint32"
            content_lines.append(
                f"local f_{safe_name} = {pf}(\"{protocol}.{safe_name}\", "
                f"\"{safe_name.capitalize()}\", base.DEC)"
            )
        elif ftype == "float":
            content_lines.append(
                f"local f_{safe_name} = ProtoField.float("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\")"
            )
        elif ftype == "double":
            content_lines.append(
                f"local f_{safe_name} = ProtoField.double("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\")"
            )
        elif ftype == "long":
            if info["min_size"] == 8:
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.uint64("
                    f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                )
            else:
                content_lines.append(
                    f"local f_{safe_name} = ProtoField.int32("
                    f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\", base.DEC)"
                )
        elif ftype == "char":
            content_lines.append(
                f"local f_{safe_name} = ProtoField.string("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\")"
            )
        elif ftype == "bitfield":
            sz = info["min_size"]
            if   sz == 1: pf = "ProtoField.uint8"
            elif sz == 2: pf = "ProtoField.uint16"
            elif sz == 4: pf = "ProtoField.uint32"
            elif sz == 8: pf = "ProtoField.uint64"
            else:         pf = "ProtoField.uint32"
            content_lines.append(
                f"local f_{safe_name} = {pf}("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()} (Bitfield)\")"
            )
        else:
            content_lines.append(
                f"local f_{safe_name} = ProtoField.string("
                f"\"{protocol}.{safe_name}\", \"{safe_name.capitalize()}\")"
            )

        # bitfield sub-fields
        bf_cnt = info.get("bitfields_count") or 0
        for i in range(bf_cnt):
            lbl = f"{safe_name.capitalize()} Bitfield {i+1}"
            content_lines.append(
                f"local f_{safe_name}_bf{i} = ProtoField.uint8("
                f"\"{protocol}.{safe_name}_bf{i}\", \"{lbl}\", base.DEC)"
            )
        if bf_cnt:
            lst = ", ".join(f"f_{safe_name}_bf{i}" for i in range(bf_cnt))
            content_lines.append(f"local bf_fields_{safe_name} = {{ {lst} }}")

    # 4) Now declare each object’s sub-fields under its group
    for obj, subdict in object_fields.items():
        for subf, info in subdict.items():
            ftype = info["field_type"]
                        # Static array parsing
            is_dyn = info.get("is_dynamic_array", False)
            if is_dyn:
                size_field = info["size_defining_field"]
             # dynamic code
                 # Static array parsing
                # — treat any field that has a size_defining_field as a dynamic array —
                if "size_defining_field" in info:
                    size_field = info["size_defining_field"]
                    content_lines.append(f"    -- Dynamic field: {safe_name}")
                    content_lines.append(f"    local length = field_values['{size_field}']")
                    content_lines.append(f"    if buffer:len() < offset + length then")
                    content_lines.append(
                        f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Not enough bytes for dynamic {safe_name}\")"
                    )
                    content_lines.append("        return")
                    content_lines.append("    end")
                    content_lines.append(
                        f"    local dyn_tree = subtree:add(f_{safe_name}, buffer(offset, length))"
                    )
                    # remember the parsed length if you want to show it later
                    content_lines.append(f"    field_values['{safe_name}'] = length")
                    content_lines.append("    offset = offset + length\n")
                    continue


            # ---- object array support ----
            if ftype.startswith("array of"):
                elem_type = ftype[len("array of"):].strip()
                sizes     = info.get("min_size", [])
                count     = len(sizes)

                # parent
                if elem_type == "char":
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.string("
                        f"\"{protocol}.{obj}.{subf}\", \"{subf}\")"
                    )
                else:
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.bytes("
                        f"\"{protocol}.{obj}.{subf}\", \"{subf}\")"
                    )

                # elements
                for i in range(count):
                    size_i = int(sizes[i])
                    if elem_type in ["short", "int"]:
                        if   size_i == 1: pftype = "ProtoField.uint8"
                        elif size_i == 2: pftype = "ProtoField.uint16"
                        elif size_i == 4: pftype = "ProtoField.uint32"
                        else:             pftype = "ProtoField.uint32"
                        base = ", base.DEC"
                    elif elem_type == "float":
                        pftype, base = "ProtoField.float", ""
                    elif elem_type == "double":
                        pftype, base = "ProtoField.double", ""
                    else:
                        pftype, base = "ProtoField.string", ""
                    content_lines.append(
                        f"local f_{obj}_{subf}_{i} = {pftype}(\"{protocol}.{obj}.{subf}_{i}\", "
                        f"\"{subf}[{i}]\"){base}"
                    )
                continue
            # ---- end object array support ----

            # ---- object scalar & bitfield ----
            if info["field_type"] == "bool":
                content_lines.append(
                    f"local f_{obj}_{subf} = ProtoField.uint8("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                )
            elif info["field_type"] == "int":
                sz = info["min_size"]
                if   sz == 1: pf = "ProtoField.uint8"
                elif sz == 2: pf = "ProtoField.uint16"
                elif sz == 4: pf = "ProtoField.uint32"
                elif sz == 8: pf = "ProtoField.uint64"
                else:         pf = "ProtoField.uint32"
                content_lines.append(
                    f"local f_{obj}_{subf} = {pf}(\"{protocol}.{obj}.{subf}\", "
                    f"\"{subf.capitalize()}\", base.DEC)"
                )
            elif info["field_type"] == "float":
                content_lines.append(
                    f"local f_{obj}_{subf} = ProtoField.float("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                )
            elif info["field_type"] == "double":
                content_lines.append(
                    f"local f_{obj}_{subf} = ProtoField.double("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                )
            elif info["field_type"] == "long":
                if info["min_size"] == 8:
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.uint64("
                        f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                    )
                else:
                    content_lines.append(
                        f"local f_{obj}_{subf} = ProtoField.int32("
                        f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\", base.DEC)"
                    )
            elif info["field_type"] == "char":
                content_lines.append(
                    f"local f_{obj}_{subf} = ProtoField.string("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                )
            elif info["field_type"] == "bitfield":
                sz = info["min_size"]
                if   sz == 1: pf = "ProtoField.uint8"
                elif sz == 2: pf = "ProtoField.uint16"
                elif sz == 4: pf = "ProtoField.uint32"
                elif sz == 8: pf = "ProtoField.uint64"
                else:         pf = "ProtoField.uint32"
                content_lines.append(
                    f"local f_{obj}_{subf} = {pf}("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()} (Bitfield)\")"
                )
            else:
                content_lines.append(
                    f"local f_{obj}_{subf} = ProtoField.string("
                    f"\"{protocol}.{obj}.{subf}\", \"{subf.capitalize()}\")"
                )

            # bitfield sub-fields for object field
            bf_cnt = info.get("bitfields_count") or 0
            for i in range(bf_cnt):
                lbl = f"{subf.capitalize()} Bitfield {i+1}"
                content_lines.append(
                    f"local f_{obj}_{subf}_bf{i} = ProtoField.uint8("
                    f"\"{protocol}.{obj}.{subf}_bf{i}\", \"{lbl}\", base.DEC)"
                )
            if bf_cnt:
                lst = ", ".join(f"f_{obj}_{subf}_bf{i}" for i in range(bf_cnt))
                content_lines.append(f"local bf_fields_{obj}_{subf} = {{ {lst} }}")

    # blank line and register all fields
    content_lines.append("")
    all_fields = generate_field_list(fields)
    content_lines.append(f"{protocol}.fields = {{ {', '.join(all_fields)} }}\n")


    # --- Now, INSIDE the static dissector function, after subtree and offset lines, add: ---

    




    # Dissector function
    content_lines.append(f"function {protocol}.dissector(buffer, pinfo, tree)")
    content_lines.append("    if buffer:len() == 0 then return end")
    content_lines.append(f"    pinfo.cols.protocol = \"{protocol}\"")
    content_lines.append(f"    local subtree = tree:add({protocol}, buffer(), \"{protocol}\")")
    content_lines.append("    local offset = 0")
    # Helpers
    content_lines.append("    -- popcount helper")
    content_lines.append("    local function popcount(x)")
    content_lines.append("        local cnt = 0")
    content_lines.append("        while x > 0 do cnt = cnt + (x % 2); x = math.floor(x/2) end")
    content_lines.append("        return cnt")
    content_lines.append("    end\n")

    content_lines.append("    -- to_binary_str helper")
    content_lines.append("    local function to_binary_str(num, bits)")
    content_lines.append("        local s = \"\"")
    content_lines.append("        for i = bits-1, 0, -1 do")
    content_lines.append("            local b = bit.rshift(num, i)")
    content_lines.append("            s = s .. ((bit.band(b,1)==1) and \"1\" or \"0\")")
    content_lines.append("        end")
    content_lines.append("        return s")
    content_lines.append("    end\n")


    content_lines.append("    -- Object groups (static)")
    for obj in object_fields:
        content_lines.append(f"    local {obj}_tree = subtree:add(f_{obj}, buffer())")
        for subf, info in object_fields[obj].items():
            ftype = info["field_type"]
            if ftype == "bitfield":
                    size = info["min_size"]
                    cnt  = info["bitfields_count"]
                    content_lines.append(f"    -- Bitfield field: {obj}.{subf}")
                    content_lines.append(f"    if buffer:len() < offset + {size} then")
                    content_lines.append(
                        f"        {obj}_tree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Not enough bytes for {subf}\")"
                    )
                    content_lines.append("    else")
                    if size == 8:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint64()")
                    else:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint()")
                    content_lines.append(
                        f"        local item = {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {size}))"
                    )
                    content_lines.append("        local actual = popcount(val)")
                    content_lines.append(
                        f"        item:append_text(\" (\"..to_binary_str(val, {size}*8)..\")\")"
                    )
                    content_lines.append(f"        offset = offset + {size}")
                    content_lines.append("    end")

            elif ftype.startswith("array of"):
                sizes    = info.get("min_size", [])
                total_len = sum(int(s) for s in sizes)
                content_lines.append(f"    local arr_tree = {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {total_len}))")
                content_lines.append("    local elt_off = 0")
                for i, sz in enumerate(sizes):
                    content_lines.append(f"    arr_tree:add(f_{obj}_{subf}_{i}, buffer(offset + elt_off, {int(sz)}))")
                    content_lines.append(f"    elt_off = elt_off + {int(sz)}")
                content_lines.append(f"    offset = offset + {total_len}")
            else:
                size = int(info.get("min_size", 0))
                content_lines.append(f"    {obj}_tree:add(f_{obj}_{subf}, buffer(offset, {size}))")
                
                # advance the offset for the next field!
                content_lines.append(f"    offset = offset + {size}")


    content_lines.append("    local field_values = {}\n")

    
    # Parse each field
    for field_name, info in simple_fields.items():
        ftype = info["field_type"]
        safe_name = field_name.replace(".", "_")
        # Static array parsing
        is_dyn = info.get("is_dynamic_array", False)
        if is_dyn:
            size_field = info["size_defining_field"]  # the name of the earlier field
            content_lines.append(f"    -- Dynamic field: {safe_name}")
            # pull the length out of the field_values table:
            content_lines.append(f"    local length = field_values['{size_field}']")
            content_lines.append(f"    if buffer:len() < offset + length then")
            content_lines.append(
                f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                f"\"Not enough bytes for dynamic {safe_name}\")"
            )
            content_lines.append("        return")
            content_lines.append("    end")
            content_lines.append(
                f"    local dyn_tree = subtree:add(f_{safe_name}, buffer(offset, length))"
            )
            content_lines.append("    offset = offset + length\n")
            continue
        if ftype.startswith("array of"):
            sizes    = info.get("min_size", [])
            total_len = sum(int(s) for s in sizes)

            content_lines.append(f"    -- Array: {safe_name}")
            content_lines.append(f"    if buffer:len() < offset + {total_len} then")
            content_lines.append(
                f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                f"\"Not enough bytes for array {safe_name}\")"
            )
            content_lines.append("        return")
            content_lines.append("    end\n")

            # Parent node
            content_lines.append(
                f"    local arr_tree = subtree:add(f_{safe_name}, buffer(offset, {total_len}))"
            )
            content_lines.append("    local elt_off = 0")
            for i in range(len(sizes)):
                size_i = int(sizes[i])
                content_lines.append(
                    f"    arr_tree:add(f_{safe_name}_{i}, buffer(offset + elt_off, {size_i}))"
                )
                content_lines.append(f"    elt_off = elt_off + {size_i}")
            content_lines.append(f"    offset = offset + {total_len}\n")
            continue
        # … inside the loop, before your else: …
        elif ftype == "bitfield":
                    size = info["min_size"]
                    cnt  = info["bitfields_count"]
                    content_lines.append(f"    -- Bitfield field: {safe_name}")
                    content_lines.append(f"    if buffer:len() < offset + {size} then")
                    content_lines.append(
                        f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Not enough bytes for {safe_name}\")"
                    )
                    content_lines.append("    else")
                    if size == 8:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint64()")
                    else:
                        content_lines.append(f"        local val = buffer(offset, {size}):uint()")
                    content_lines.append(
                        f"        local item = subtree:add(f_{safe_name}, buffer(offset, {size}))"
                    )
                    content_lines.append("        local actual = popcount(val)")
                    content_lines.append(
                        f"        item:append_text(\" (\"..to_binary_str(val, {size}*8)..\")\")"
                    )
                    content_lines.append(f"        offset = offset + {size}")
                    content_lines.append("    end")
                    continue

        # Scalar & bitfield parsing
        content_lines.append(f"    -- Field: {safe_name}")
        content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
        content_lines.append(
            f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
            f"\"Not enough bytes for {safe_name}\")"
        )
        content_lines.append("        return")
        content_lines.append("    end")

        if ftype in ["int","bool","long"]:
            if info["min_size"] == 8:
                content_lines.append(
                    f"    local {safe_name} = buffer(offset, {info['min_size']}):uint64()"
                )
            else:
                content_lines.append(
                    f"    local {safe_name} = buffer(offset, {info['min_size']}):uint()"
                )
        elif ftype == "float":
            content_lines.append(
                f"    local raw = buffer(offset, {info['min_size']}):bytes():raw()"
            )
            content_lines.append(
                f"    local {safe_name} = string.unpack(\">f\", raw)"
            )
        elif ftype == "double":
            content_lines.append(
                f"    local raw = buffer(offset, {info['min_size']}):bytes():raw()"
            )
            content_lines.append(
                f"    local {safe_name} = string.unpack(\">d\", raw)"
            )
        
        else:
            content_lines.append(
                f"    local {safe_name} = buffer(offset, {info['min_size']}):string()"
            )

        content_lines.append(
            f"    subtree:add(f_{safe_name}, buffer(offset, {info['min_size']}))"
        )
        content_lines.append(f"    field_values['{safe_name}'] = {safe_name}")
        content_lines.append(f"    offset = offset + {info['min_size']}\n")

    # Assemble Info column
    content_lines.append("    -- assemble info column")
    content_lines.append("    local parts = {}")
    content_lines.append("    for k,v in pairs(field_values) do table.insert(parts, k..\"=\"..tostring(v)) end")
    content_lines.append("    pinfo.cols.info = \"Static: \" .. table.concat(parts, \", \")")
    content_lines.append("end\n")

    # Register dissector
    content_lines.append("-- Register this dissector for the UDP port")
    content_lines.append("local udp_port = DissectorTable.get(\"udp.port\")")
    content_lines.append(f"udp_port:add(10000, {protocol})\n")

    # Save to MongoDB
    document = {
        "filename": static_filename,
        "content": "\n".join(content_lines)
    }
    collection.insert_one(document)
    print(f"Inserted static dissector document: {static_filename}")

