set -x

target_id=$(curl http://localhost:5000/api/target -d '{"architecture": "x86_64", "os": "Windows 10", "target_executable": "wmp"}' -H 'Content-Type: application/json' | sed 's/^.*"id": \([0-9]*\)[,}].*$/\1/')

curl http://localhost:5000/api/config -d "{\"target_id\": ${target_id}, \"name\": \"driver_opts_wmp\", \"value\": \"{\\\"path\\\": \\\"C:\\\\\\\\Program Files\\\\\\\\Windows Media Player\\\\\\\\wmplayer.exe\\\"}\"}" -H 'Content-Type: application/json'

curl http://localhost:5000/api/config -d "{\"target_id\": ${target_id}, \"name\": \"instrumentation_opts_dynamorio\", \"value\": \"{\\\"per_module_coverage\\\": 1, \\\"timeout\\\": 10000, \\\"coverage_modules\\\": [\\\"wmp.DLL\\\"], \\\"client_params\\\": \\\"-target_module wmplayer.exe -target_offset 0x1F20 -nargs 3\\\", \\\"fuzz_iterations\\\": 1, \\\"target_path\\\": \\\"C:\\\\\\\\Program Files\\\\\\\\Windows Media Player\\\\\\\\wmplayer.exe\\\"}\"}" -H 'Content-Type: application/json'

input_id=$(curl http://localhost:5000/api/file -d '{"content": "Example seed file"}' -H 'Content-Type: application/json' | sed 's/^.*"input_id": \([0-9]*\)[,}].*$/\1/')

curl http://localhost:5000/api/job -d "{\"job_type\": \"fuzz\", \"target_id\": ${target_id}, \"mutator\": \"radamsa\", \"instrumentation_type\": \"dynamorio\", \"driver\": \"wmp\", \"input_ids\": [${input_id}]}" -H 'Content-Type: application/json'

