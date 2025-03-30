-- Import JSON and CSV modules
local json = require("dkjson")

-- Function to process a single log line
function process_log_line(line, output_csv, log_output_file)
    local log_entry, _, err = json.decode(line)
    if log_entry then
        local log_data = {
            log_entry.timestamp or "",
            log_entry.src_ip or "",
            log_entry.eventid or "",
            log_entry.username or "",
            log_entry.sensor or "",
            log_entry.dest_port or "",
            log_entry.password or ""
        }
        
        -- Append log to CSV file
        local f = io.open(output_csv, "a")
        if f then
            f:write(table.concat(log_data, ",") .. "\n")
            f:close()
        else
            print("Error: Unable to open CSV file: " .. output_csv)
        end
        
        -- Append log to log file
        local log_f = io.open(log_output_file, "a")
        if log_f then
            log_f:write("{" .. table.concat(log_data, ", ") .. "}\n")
            log_f:close()
        else
            print("Error: Unable to open log output file: " .. log_output_file)
        end
    else
        print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
    end
end

-- Main real-time log processing
function monitor_honeypot_logs(json_filename, output_csv, log_output_file)
    local f = io.open(json_filename, "r")
    if not f then
        print("Error: Unable to open honeypot log file: " .. json_filename)
        return
    end
    
    -- Move to the end of the file to process new logs in real time
    f:seek("end")
    print("🔄 Real-time monitoring started for " .. json_filename)
    
    while true do
        local line = f:read("*l")  -- Read new line
        if line then
            process_log_line(line, output_csv, log_output_file)
            print("CSV file :", output_csv)
        else
            os.execute("sleep 2")  -- Wait before checking again
        end
    end
    
    f:close()
end

-- Define file paths
local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
local output_csv = "/home/user/honeypot/honeypot_logs.csv"
local log_output_file = "/home/user/honeypot/processed_logs.log"

-- Start monitoring logs
monitor_honeypot_logs(honeypot_log_file, output_csv, log_output_file)

