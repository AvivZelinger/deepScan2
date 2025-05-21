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
JSON_FILENAME = "/mnt/c/Users/aviv/Desktop/Final_Project/server/dpi_output.json"

# Load the DPI specification
with open(JSON_FILENAME, "r") as f:
    dpi_spec = json.load(f)

protocol = dpi_spec.get("protocol", "CustomProtocol")
dpi_data = dpi_spec.get("dpi", {})

##########################################################################
# Helper function to generate the list of all fields (including bitfields and arrays)
##########################################################################
def generate_field_list(fields):
    all_fields = []
    for field_name, info in fields.items():
        ftype = info.get("field_type", "")
        # support fixed arrays: one parent + one per element
        if ftype.startswith("array of"):
            # parent entry
            all_fields.append(f"f_{field_name}")
            # then each element
            count = len(info.get("min_size", []))
            for i in range(count):
                all_fields.append(f"f_{field_name}_{i}")
            continue

        # scalar & bitfield as before
        all_fields.append(f"f_{field_name}")
        if info.get("field_type") != "bitfield":
            bf = info.get("bitfields_count") or 0
            for i in range(bf):
                all_fields.append(f"f_{field_name}_bf{i}")
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

        # Declare ProtoFields for each field (including arrays)
        for field_name, info in fields.items():
            ftype = info["field_type"]

            # ----- array support -----
            if ftype.startswith("array of"):
                elem_type = ftype[len("array of"):].strip()   # e.g. "short" or "char"
                sizes     = info.get("min_size", [])
                count     = len(sizes)

                # 1) Declare the parent field for the whole array
                if elem_type == "char":
                    content_lines.append(
                        f"local f_{field_name} = ProtoField.string("
                        f"\"{proto_name}.{field_name}\", \"{field_name}\")"
                    )
                else:
                    content_lines.append(
                        f"local f_{field_name} = ProtoField.bytes("
                        f"\"{proto_name}.{field_name}\", \"{field_name}\")"
                    )

                # 2) Then each element as its own ProtoField
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
                        f"local f_{field_name}_{i} = {pftype}(\"{proto_name}.{field_name}_{i}\", "
                        f"\"{field_name}[{i}]\"){base}"
                    )

                continue
            # ----- end array support -----


            # existing scalar & bitfield declarations
            if ftype == "bool":
                proto_field_type = "ProtoField.uint8"
                base = ", base.DEC"
                content_lines.append(
                    f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\"){base}"
                )
            elif ftype == "int":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ", base.DEC"
                content_lines.append(
                    f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\"){base}"
                )
            elif ftype == "float":
                content_lines.append(
                    f"local f_{field_name} = ProtoField.float(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\")"
                )
            elif ftype == "double":
                content_lines.append(
                    f"local f_{field_name} = ProtoField.double(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\")"
                )
            elif ftype == "long":
                if info["min_size"] == 8:
                    content_lines.append(
                        f"local f_{field_name} = ProtoField.uint64(\"{proto_name}.{field_name}\", "
                        f"\"{field_name.capitalize()}\", base.DEC)"
                    )
                else:
                    content_lines.append(
                        f"local f_{field_name} = ProtoField.int32(\"{proto_name}.{field_name}\", "
                        f"\"{field_name.capitalize()}\", base.DEC)"
                    )
            elif ftype == "char":
                content_lines.append(
                    f"local f_{field_name} = ProtoField.string(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\")"
                )
            elif ftype == "bitfield":
                size = info["min_size"]
                if size == 1:
                    proto_field_type = "ProtoField.uint8"
                elif size == 2:
                    proto_field_type = "ProtoField.uint16"
                elif size == 4:
                    proto_field_type = "ProtoField.uint32"
                elif size == 8:
                    proto_field_type = "ProtoField.uint64"
                else:
                    proto_field_type = "ProtoField.uint32"
                base = ""
                content_lines.append(
                    f"local f_{field_name} = {proto_field_type}(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()} (Bitfield)\"){base}"
                )
            else:
                content_lines.append(
                    f"local f_{field_name} = ProtoField.string(\"{proto_name}.{field_name}\", "
                    f"\"{field_name.capitalize()}\")"
                )

            # For non-bitfield types with bitfields_count defined, declare additional ProtoFields.
            if info.get("field_type") != "bitfield":
                bitfields_count = info.get("bitfields_count") or 0
                for i in range(bitfields_count):
                    bf_label = f"{field_name.capitalize()} Bitfield {i+1}"
                    content_lines.append(
                        f"local f_{field_name}_bf{i} = ProtoField.uint8("
                        f"\"{proto_name}.{field_name}_bf{i}\", \"{bf_label}\", base.DEC)"
                    )
                if bitfields_count:
                    bf_fields_list = ", ".join(f"f_{field_name}_bf{i}" for i in range(bitfields_count))
                    content_lines.append(f"local bf_fields_{field_name} = {{ {bf_fields_list} }}")

        content_lines.append("")
        # Register all fields (including bitfields and arrays)
        all_fields = generate_field_list(fields)
        content_lines.append(f"{proto_name}.fields = {{ {', '.join(all_fields)} }}\n")

        # Begin dissector function and add helper functions for bitfield processing
        content_lines.append(f"function {proto_name}.dissector(buffer, pinfo, tree)")
        content_lines.append("    if buffer:len() == 0 then return end")
        content_lines.append(f"    pinfo.cols.protocol = \"{protocol}\"")
        content_lines.append(
            f"    local subtree = tree:add({proto_name}, buffer(), "
            f"\"{protocol} for IP {ip} at {percentage}\")"
        )
        content_lines.append("    local offset = 0")
        content_lines.append("    local dpi_error = false")
        content_lines.append("    local error_messages = {}")
        content_lines.append("    local parsed_values = {}\n")

        # Helper functions for bitfield type
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

        # Parse each field (with array support)
        for field_name, info in fields.items():
            ftype = info["field_type"]

             # ----- array parsing support -----
            if ftype.startswith("array of"):
                sizes    = info.get("min_size", [])
                total_len = sum(int(s) for s in sizes)

                content_lines.append(f"    -- Array: {field_name}")
                content_lines.append(f"    if buffer:len() < offset + {total_len} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for array {field_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append("        return")
                content_lines.append("    end\n")

                # parent covers entire slice
                content_lines.append(
                    f"    local arr_tree = subtree:add(f_{field_name}, buffer(offset, {total_len}))"
                )
                content_lines.append("    local elt_off = 0")
                for i in range(len(sizes)):
                    size_i = int(sizes[i])
                    content_lines.append(
                        f"    arr_tree:add(f_{field_name}_{i}, buffer(offset + elt_off, {size_i}))"
                    )
                    content_lines.append(f"    elt_off = elt_off + {size_i}")
                content_lines.append(f"    offset = offset + {total_len}\n")
                continue
            # ----- end array parsing support -----


            # existing bitfield, scalar, and dynamic array branches...
            if ftype == "bitfield":
                # (original bitfield parsing code here)
                content_lines.append(f"    -- Field: {field_name}")
                content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {field_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")")
                content_lines.append("        return")
                content_lines.append("    end")
                if info["min_size"] == 8:
                    content_lines.append(
                        f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()"
                    )
                else:
                    content_lines.append(
                        f"    local {field_name} = buffer(offset, {info['min_size']}):uint()"
                    )
                content_lines.append(
                    f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))"
                )
                content_lines.append(f"    local num_bits = {info['min_size']} * 8")
                content_lines.append(f"    local actual_bit_count = popcount({field_name})")
                content_lines.append(
                    f"    if actual_bit_count ~= {info['bitfields_count']} then"
                )
                content_lines.append(
                    f"        {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, "
                    f"\"Bitfield {field_name} expected {info['bitfields_count']} bits set, got \" .. actual_bit_count)"
                )
                content_lines.append("    end")
                content_lines.append(
                    f"    local binary_str = to_binary_str({field_name}, num_bits)"
                )
                content_lines.append(
                    f"    {field_name}_item:append_text(\" (\" .. binary_str .. \")\")"
                )
                content_lines.append(f"    parsed_values['{field_name}'] = binary_str")
                content_lines.append(f"    offset = offset + {info['min_size']}\n")

            elif not info.get("is_dynamic_array", False):
                # (original scalar parsing code here including range checks and bitfield slices)
                content_lines.append(f"    -- Field: {field_name}")
                content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {field_name}\")"
                )
                content_lines.append("        return")
                content_lines.append("    end")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        content_lines.append(
                            f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()"
                        )
                    else:
                        content_lines.append(
                            f"    local {field_name} = buffer(offset, {info['min_size']}):uint()"
                        )
                elif ftype == "float":
                    content_lines.append(
                        f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)"
                    )
                elif ftype == "double":
                    content_lines.append(
                        f"    local {field_name}_bytes = buffer(offset, {info['min_size']}):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)"
                    )
                else:
                    content_lines.append(
                        f"    local {field_name} = buffer(offset, {info['min_size']}):string()"
                    )
                content_lines.append(
                    f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))"
                )
                content_lines.append(f"    parsed_values['{field_name}'] = {field_name}")
                if ftype in ["int", "bool", "long", "float", "double"] and \
                   info.get("min_value") is not None and info.get("max_value") is not None:
                    content_lines.append("    do")
                    content_lines.append(f"        local min_val = {info['min_value']}")
                    content_lines.append(f"        local max_val = {info['max_value']}")
                    content_lines.append(
                        f"        if {field_name} < min_val or {field_name} > max_val then"
                    )
                    content_lines.append(
                        f"            {field_name}_item:add_expert_info(PI_MALFORMED, PI_ERROR, "
                        f"\"Value out of range for {field_name}\")"
                    )
                    content_lines.append("            dpi_error = true")
                    content_lines.append(
                        f"            table.insert(error_messages, \"{field_name} out of range\")"
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
                        f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)"
                    )
                    content_lines.append(
                        f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)"
                    )
                    content_lines.append(
                        f"            parsed_values['{field_name}_bf' .. i] = bf_value"
                    )
                    content_lines.append("        end")
                    content_lines.append("    end\n")

            else:
                # dynamic array parsing (unchanged)
                size_field = info["size_defining_field"]
                content_lines.append(f"    -- Dynamic array: {field_name}")
                content_lines.append(f"    local dynamic_length = {size_field}")
                content_lines.append(
                    f"    if dynamic_length < {info['min_size']} or dynamic_length > {info['max_size']} then"
                )
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"{field_name} length out of range\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, \"{field_name} length out of range\")"
                )
                content_lines.append("    end")
                content_lines.append(
                    f"    if buffer:len() < offset + dynamic_length then"
                )
                content_lines.append(
                    f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                    f"\"Not enough bytes for {field_name}\")"
                )
                content_lines.append("        dpi_error = true")
                content_lines.append(
                    f"        table.insert(error_messages, \"Not enough bytes for {field_name}\")"
                )
                content_lines.append("        return")
                content_lines.append("    end")
                if ftype in ["int", "bool", "long"]:
                    if info["min_size"] == 8:
                        content_lines.append(
                            f"    local {field_name} = buffer(offset, dynamic_length):uint64()"
                        )
                    else:
                        content_lines.append(
                            f"    local {field_name} = buffer(offset, dynamic_length):uint()"
                        )
                elif ftype == "float":
                    content_lines.append(
                        f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {field_name} = string.unpack(\">f\", {field_name}_bytes)"
                    )
                elif ftype == "double":
                    content_lines.append(
                        f"    local {field_name}_bytes = buffer(offset, dynamic_length):bytes():raw()"
                    )
                    content_lines.append(
                        f"    local {field_name} = string.unpack(\">d\", {field_name}_bytes)"
                    )
                else:
                    content_lines.append(
                        f"    local {field_name} = buffer(offset, dynamic_length):string()"
                    )
                content_lines.append(
                    f"    local {field_name}_item = subtree:add(f_{field_name}, buffer(offset, dynamic_length))"
                )
                content_lines.append(f"    parsed_values['{field_name}'] = {field_name}")
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
                        f"            local bf_value = bit.band(bit.rshift({field_name}, shift), mask)"
                    )
                    content_lines.append(
                        f"            subtree:add(bf_fields_{field_name}[i+1], bf_value)"
                    )
                    content_lines.append(
                        f"            parsed_values['{field_name}_bf' .. i] = bf_value"
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

    # Declare ProtoFields (including fixed arrays)
    for field_name, info in fields.items():
        ftype = info["field_type"]

        # ----- array support in static loop -----
        if ftype.startswith("array of"):
            elem_type = ftype[len("array of"):].strip()   # e.g. "short" or "char"
            sizes     = info.get("min_size", [])
            count     = len(sizes)

            # 1) Parent field covering the entire array
            if elem_type == "char":
                content_lines.append(
                    f"local f_{field_name} = ProtoField.string("
                    f"\"{protocol}.{field_name}\", \"{field_name}\")"
                )
            else:
                content_lines.append(
                    f"local f_{field_name} = ProtoField.bytes("
                    f"\"{protocol}.{field_name}\", \"{field_name}\")"
                )

            # 2) Each element as its own ProtoField
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
                    f"local f_{field_name}_{i} = {pftype}(\"{protocol}.{field_name}_{i}\", "
                    f"\"{field_name}[{i}]\"){base}"
                )

            continue
        # ----- end array support -----

        # Scalar & bitfield declarations
        if ftype == "bool":
            content_lines.append(
                f"local f_{field_name} = ProtoField.uint8("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)"
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
                f"local f_{field_name} = {pf}(\"{protocol}.{field_name}\", "
                f"\"{field_name.capitalize()}\", base.DEC)"
            )
        elif ftype == "float":
            content_lines.append(
                f"local f_{field_name} = ProtoField.float("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")"
            )
        elif ftype == "double":
            content_lines.append(
                f"local f_{field_name} = ProtoField.double("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")"
            )
        elif ftype == "long":
            if info["min_size"] == 8:
                content_lines.append(
                    f"local f_{field_name} = ProtoField.uint64("
                    f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)"
                )
            else:
                content_lines.append(
                    f"local f_{field_name} = ProtoField.int32("
                    f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\", base.DEC)"
                )
        elif ftype == "char":
            content_lines.append(
                f"local f_{field_name} = ProtoField.string("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")"
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
                f"local f_{field_name} = {pf}("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()} (Bitfield)\")"
            )
        else:
            content_lines.append(
                f"local f_{field_name} = ProtoField.string("
                f"\"{protocol}.{field_name}\", \"{field_name.capitalize()}\")"
            )

        # Per‐field bitfield sub‐fields
        if ftype != "bitfield":
            bf_cnt = info.get("bitfields_count") or 0
            for i in range(bf_cnt):
                lbl = f"{field_name.capitalize()} Bitfield {i+1}"
                content_lines.append(
                    f"local f_{field_name}_bf{i} = ProtoField.uint8("
                    f"\"{protocol}.{field_name}_bf{i}\", \"{lbl}\", base.DEC)"
                )
            if bf_cnt:
                lst = ", ".join(f"f_{field_name}_bf{i}" for i in range(bf_cnt))
                content_lines.append(f"local bf_fields_{field_name} = {{ {lst} }}")

    # Register all fields
    content_lines.append("")
    all_fields = generate_field_list(fields)
    content_lines.append(f"{protocol}.fields = {{ {', '.join(all_fields)} }}\n")

    # Dissector function
    content_lines.append(f"function {protocol}.dissector(buffer, pinfo, tree)")
    content_lines.append("    if buffer:len() == 0 then return end")
    content_lines.append(f"    pinfo.cols.protocol = \"{protocol}\"")
    content_lines.append(f"    local subtree = tree:add({protocol}, buffer(), \"{protocol}\")")
    content_lines.append("    local offset = 0")
    content_lines.append("    local field_values = {}\n")

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

    # Parse each field
    for field_name, info in fields.items():
        ftype = info["field_type"]

        # Static array parsing
        if ftype.startswith("array of"):
            sizes    = info.get("min_size", [])
            total_len = sum(int(s) for s in sizes)

            content_lines.append(f"    -- Array: {field_name}")
            content_lines.append(f"    if buffer:len() < offset + {total_len} then")
            content_lines.append(
                f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
                f"\"Not enough bytes for array {field_name}\")"
            )
            content_lines.append("        return")
            content_lines.append("    end\n")

            # Parent node
            content_lines.append(
                f"    local arr_tree = subtree:add(f_{field_name}, buffer(offset, {total_len}))"
            )
            content_lines.append("    local elt_off = 0")
            for i in range(len(sizes)):
                size_i = int(sizes[i])
                content_lines.append(
                    f"    arr_tree:add(f_{field_name}_{i}, buffer(offset + elt_off, {size_i}))"
                )
                content_lines.append(f"    elt_off = elt_off + {size_i}")
            content_lines.append(f"    offset = offset + {total_len}\n")
            continue

        # Scalar & bitfield parsing
        content_lines.append(f"    -- Field: {field_name}")
        content_lines.append(f"    if buffer:len() < offset + {info['min_size']} then")
        content_lines.append(
            f"        subtree:add_expert_info(PI_MALFORMED, PI_ERROR, "
            f"\"Not enough bytes for {field_name}\")"
        )
        content_lines.append("        return")
        content_lines.append("    end")

        if ftype in ["int","bool","long"]:
            if info["min_size"] == 8:
                content_lines.append(
                    f"    local {field_name} = buffer(offset, {info['min_size']}):uint64()"
                )
            else:
                content_lines.append(
                    f"    local {field_name} = buffer(offset, {info['min_size']}):uint()"
                )
        elif ftype == "float":
            content_lines.append(
                f"    local raw = buffer(offset, {info['min_size']}):bytes():raw()"
            )
            content_lines.append(
                f"    local {field_name} = string.unpack(\">f\", raw)"
            )
        elif ftype == "double":
            content_lines.append(
                f"    local raw = buffer(offset, {info['min_size']}):bytes():raw()"
            )
            content_lines.append(
                f"    local {field_name} = string.unpack(\">d\", raw)"
            )
        else:
            content_lines.append(
                f"    local {field_name} = buffer(offset, {info['min_size']}):string()"
            )

        content_lines.append(
            f"    subtree:add(f_{field_name}, buffer(offset, {info['min_size']}))"
        )
        content_lines.append(f"    field_values['{field_name}'] = {field_name}")
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
