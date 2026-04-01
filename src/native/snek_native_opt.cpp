#include <stdint.h>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

extern "C" {
    uint32_t snek_optimize_dataflow(uint32_t* pcode_buffer, uint32_t length) {
        if (length == 0 || pcode_buffer == nullptr) return 0;

        uint32_t optimized_count = 0;

        for (uint32_t i = 0; i + 2 < length; i += 3) {
            uint32_t opcode = pcode_buffer[i];
            uint32_t op1 = pcode_buffer[i+1];
            uint32_t op2 = pcode_buffer[i+2];

            if (opcode == 0 && op1 == op2) {
                pcode_buffer[i] = 999;
                optimized_count++;
            }

            if (opcode == 1 && op2 == 0) {
                pcode_buffer[i] = 0;
                optimized_count++;
            }
        }

        std::unordered_map<uint32_t, uint32_t> def_map;
        std::unordered_set<uint32_t> used_vars;

        for (uint32_t i = 0; i + 2 < length; i += 3) {
            uint32_t opcode = pcode_buffer[i];
            if (opcode == 999) continue;

            uint32_t op1 = pcode_buffer[i+1];
            uint32_t op2 = pcode_buffer[i+2];

            if (opcode == 0 || opcode == 1) {
                def_map[op1] = i;
            }

            used_vars.insert(op1);
            used_vars.insert(op2);
        }

        for (auto it = def_map.begin(); it != def_map.end(); ) {
            uint32_t var = it->first;
            uint32_t idx = it->second;
            if (used_vars.find(var) == used_vars.end()) {
                pcode_buffer[idx] = 999;
                optimized_count++;
                it = def_map.erase(it);
            } else {
                ++it;
            }
        }

        std::unordered_map<uint32_t, uint32_t> const_map;

        for (uint32_t i = 0; i + 2 < length; i += 3) {
            uint32_t opcode = pcode_buffer[i];
            if (opcode == 999) continue;

            uint32_t op1 = pcode_buffer[i+1];
            uint32_t op2 = pcode_buffer[i+2];

            if (opcode == 1) {
                auto it = const_map.find(op2);
                if (it != const_map.end()) {
                    pcode_buffer[i+2] = it->second;
                    optimized_count++;
                }
            }

            if (opcode == 0) {
                auto it = const_map.find(op2);
                if (it != const_map.end()) {
                    const_map[op1] = it->second;
                }
            }
        }

        return optimized_count;
    }
}

