-- Import JSON and CSV modules
local json = require("dkjson")

-- Function to fetch logs from honeypot log file (cowrie.json)
function fetch_honeypot_logs(json_filename)
    local logs = {}
    local f = io.open(json_filename, "r")
    if not f then
        print("Error: Unable to open honeypot log file: " .. json_filename)
        return logs
    end
    
    for line in f:lines() do
        local log_entry, _, err = json.decode(line)
        if log_entry then
            table.insert(logs, {
                log_entry.timestamp or "",
                log_entry.src_ip or "",
                log_entry.eventid or "",
                log_entry.username or "",
                log_entry.sensor or "",
                log_entry.dest_port or "",
                log_entry.password or ""
            })
        else
            print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
        end
    end
    f:close()
    return logs
end

-- Function to save logs into a CSV file
function save_logs_to_csv(logs, output_csv)
    local f = io.open(output_csv, "w")
    if not f then
        print("Error: Unable to open output CSV file: " .. output_csv)
        return
    end
    
    -- Write header
    f:write("timestamp,src_ip,eventid,username,sensor,dest_port,password\n")
    
    -- Write log data
    for _, log in ipairs(logs) do
        f:write(table.concat(log, ",") .. "\n")
    end
    
    f:close()
    print("✅ Logs successfully saved to CSV: " .. output_csv)
end

-- Main processing:
local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
local output_csv = "/home/user/honeypot/honeypot_logs.csv"
local log_output_file = "/home/user/honeypot/processed_logs.log"

-- Fetch logs from Cowrie JSON file
local honeypot_logs = fetch_honeypot_logs(honeypot_log_file)

-- Save logs to CSV file
save_logs_to_csv(honeypot_logs, output_csv)

-- Save logs to another log file
local log_f = io.open(log_output_file, "w")
if log_f then
    for _, log in ipairs(honeypot_logs) do
        log_f:write("{" .. table.concat(log, ", ") .. "}\n")
    end
    log_f:close()
    print("✅ Logs successfully saved to log file: " .. log_output_file)
else
    print("Error: Unable to open processed logs file: " .. log_output_file)
end
