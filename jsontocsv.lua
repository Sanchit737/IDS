-- -- Import JSON and CSV modules
-- local json = require("dkjson")

-- -- Function to process a single log line
-- function process_log_line(line, output_csv, log_output_file)
--     local log_entry, _, err = json.decode(line)
--     if log_entry then
--         local log_data = {
--             log_entry.timestamp or "",
--             log_entry.src_ip or "",
--             log_entry.eventid or "",
--             log_entry.username or "",
--             log_entry.sensor or "",
--             log_entry.dest_port or "",
--             log_entry.password or ""
--         }
        
--         -- Append log to CSV file
--         local f = io.open(output_csv, "a")
--         if f then
--             f:write(table.concat(log_data, ",") .. "\n")
--             f:close()
--         else
--             print("Error: Unable to open CSV file: " .. output_csv)
--         end
        
--         -- Append log to log file
--         local log_f = io.open(log_output_file, "a")
--         if log_f then
--             log_f:write("{" .. table.concat(log_data, ", ") .. "}\n")
--             log_f:close()
--         else
--             print("Error: Unable to open log output file: " .. log_output_file)
--         end
--     else
--         print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
--     end
-- end

-- -- Main real-time log processing
-- function monitor_honeypot_logs(json_filename, output_csv, log_output_file)
--     local f = io.open(json_filename, "r")
--     if not f then
--         print("Error: Unable to open honeypot log file: " .. json_filename)
--         return
--     end
    
--     -- Move to the end of the file to process new logs in real time
--     f:seek("end")
--     print("🔄 Real-time monitoring started for " .. json_filename)
    
--     while true do
--         local line = f:read("*l")  -- Read new line
--         if line then
--             process_log_line(line, output_csv, log_output_file)
--             print("CSV file :", output_csv)
--         else
--             os.execute("sleep 2")  -- Wait before checking again
--         end
--     end
    
--     f:close()
-- end

-- -- Define file paths
-- local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
-- local output_csv = "/home/user/honeypot/honeypot_logs.csv"
-- local log_output_file = "/home/user/honeypot/processed_logs.log"

-- -- Start monitoring logs
-- monitor_honeypot_logs(honeypot_log_file, output_csv, log_output_file)





-- local json = require("dkjson")

-- -- File paths
-- local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
-- local output_csv = "/home/user/honeypot/honeypot_logs.csv"
-- local log_output_file = "/home/user/honeypot/processed_logs.log"

-- -- Function to process and append a single log line
-- local function process_log_line(line)
--     local log_entry, _, err = json.decode(line)
--     if log_entry then
--         local log_data = {
--             log_entry.timestamp or "",
--             log_entry.src_ip or "",
--             log_entry.eventid or "",
--             log_entry.username or "",
--             log_entry.sensor or "",
--             log_entry.dst_port or "",
--             log_entry.password or ""
--         }
--         -- Append to CSV file
--         local csv_f = io.open(output_csv, "a")
--         if csv_f then
--             csv_f:write(table.concat(log_data, ",") .. "\n")
--             csv_f:close()
--         else
--             print("Error: Unable to open CSV file: " .. output_csv)
--         end

--         -- Append to log file
--         local log_f = io.open(log_output_file, "a")
--         if log_f then
--             log_f:write("{" .. table.concat(log_data, ", ") .. "}\n")
--             log_f:close()
--         else
--             print("Error: Unable to open log file: " .. log_output_file)
--         end

--         print("🟢 New Log Processed: {" .. table.concat(log_data, ", ") .. "}")
--     else
--         print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
--     end
-- end

-- -- Coroutine to monitor the honeypot JSON log file in real-time
-- function monitor_honeypot_logs()
--     local f = io.open(honeypot_log_file, "r")
--     if not f then
--         print("Error: Unable to open honeypot log file: " .. honeypot_log_file)
--         return
--     end

--     -- Move to the end of the file so only new lines are processed
--     f:seek("end")
--     print("🔄 Started monitoring JSON logs...")

--     while true do
--         local line = f:read("*l")
--         if line then
--             process_log_line(line)
--         else
--             os.execute("sleep 1")  -- Wait for new entries
--         end
--         coroutine.yield()
--     end
--     f:close()
-- end

-- -- Coroutine to monitor changes in the CSV file and print new updates
-- function monitor_csv_file()
--     local last_size = 0
--     print("🔄 Started monitoring CSV file updates...")
--     while true do
--         local f = io.open(output_csv, "r")
--         if f then
--             f:seek("end")
--             local size = f:seek()  -- Get current file size
--             if size > last_size then
--                 f:seek("set", last_size)  -- Move to where we left off
--                 for line in f:lines() do
--                     print("🔵 CSV Updated: " .. line)
--                 end
--                 last_size = size
--             end
--             f:close()
--         end
--         os.execute("sleep 1")  -- Wait before checking again
--         coroutine.yield()
--     end
-- end

-- -- Create coroutines for both tasks
-- local co_json = coroutine.create(monitor_honeypot_logs)
-- local co_csv = coroutine.create(monitor_csv_file)

-- -- Main loop: resume both coroutines in a round-robin fashion
-- while true do
--     local ok1, err1 = coroutine.resume(co_json)
--     if not ok1 then print("Error in JSON monitor:", err1) end

--     local ok2, err2 = coroutine.resume(co_csv)
--     if not ok2 then print("Error in CSV monitor:", err2) end

--     os.execute("sleep 0.5")  -- Optional short delay between iterations
-- end




local json = require("dkjson")
local luasql = require("luasql.mysql")
local env = assert(luasql.mysql(), "Error: Failed to initialize LuaSQL MySQL")

-- Database credentials
local db_host = os.getenv("DB_HOST")
local db_user = os.getenv("DB_USER")
local db_pass = os.getenv("DB_PASS")
local db_name = os.getenv("DB_NAME")
local db_port = os.getenv("DB_PORT")

-- Connect to MySQL database
local conn = assert(env:connect(db_name, db_user, db_pass, db_host, db_port),
                    "Error: Failed to connect to MySQL database")

-- Ensure the database table exists for blocked attempts
conn:execute([[CREATE TABLE IF NOT EXISTS blocked_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    src_ip VARCHAR(50),
    dst_port INT,
    attempts INT,
    last_attempt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);]])

-- File paths
local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
local output_csv = "/home/user/honeypot/honeypot_logs.csv"
local log_output_file = "/home/user/honeypot/processed_logs.log"

-- Track login attempts per IP within 10 minutes
local login_attempts = {}

-- Function to process and append a single log line
local function process_log_line(line)
    local log_entry, _, err = json.decode(line)
    if log_entry then
        local timestamp = log_entry.timestamp or ""
        local src_ip = log_entry.src_ip or ""
        local eventid = log_entry.eventid or ""
        local username = log_entry.username or ""
        local sensor = log_entry.sensor or ""
        local dst_port = log_entry.dst_port or ""
        local password = log_entry.password or ""

        -- Append to CSV file
        local csv_f = io.open(output_csv, "a")
        if csv_f then
            csv_f:write(table.concat({timestamp, src_ip, eventid, username, sensor, dst_port, password}, ",") .. "\n")
            csv_f:close()
        else
            print("Error: Unable to open CSV file: " .. output_csv)
        end

        -- Append to log file
        local log_f = io.open(log_output_file, "a")
        if log_f then
            log_f:write(string.format("{%s, %s, %s, %s, %s, %s, %s}\n", timestamp, src_ip, eventid, username, sensor, dst_port, password))
            log_f:close()
        else
            print("Error: Unable to open log file: " .. log_output_file)
        end

        print("🟢 New Log Processed: {" .. table.concat({timestamp, src_ip, eventid, username, sensor, dst_port, password}, ", ") .. "}")

        -- Track login attempts per IP and port
        local current_time = os.time()
        local key = src_ip .. ":" .. dst_port

        if not login_attempts[key] then
            login_attempts[key] = {count = 1, first_attempt = current_time}
        else
            local attempt_data = login_attempts[key]
            if (current_time - attempt_data.first_attempt) <= 600 then  -- 600 seconds = 10 minutes
                attempt_data.count = attempt_data.count + 1
            else
                login_attempts[key] = {count = 1, first_attempt = current_time}
            end
        end

        -- If more than 3 attempts in 10 minutes, classify as an attack
        if login_attempts[key].count >= 4 then
            print("🚨 Alert: Multiple failed login attempts detected from " .. src_ip .. " on port " .. dst_port)

            -- Insert into the database if not already present
            local query = string.format("INSERT INTO blocked_attempts (src_ip, dst_port, attempts) VALUES ('%s', %d, %d)", 
                                        src_ip, tonumber(dst_port) or 0, login_attempts[key].count)
            local res, err = conn:execute(query)
            if not res then
                print("Error inserting blocked attempt:", err)
            else
                print("✅ Blocked attempt stored in database!")
            end
        end
    else
        print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
    end
end

-- Coroutine to monitor the honeypot JSON log file in real-time
function monitor_honeypot_logs()
    local f = io.open(honeypot_log_file, "r")
    if not f then
        print("Error: Unable to open honeypot log file: " .. honeypot_log_file)
        return
    end

    f:seek("end")  -- Move to the end of the file
    print("🔄 Started monitoring JSON logs...")

    while true do
        local line = f:read("*l")
        if line then
            process_log_line(line)
        else
            os.execute("sleep 1")  -- Wait for new entries
        end
        coroutine.yield()
    end
    f:close()
end

-- Coroutine to monitor changes in the CSV file and print new updates
function monitor_csv_file()
    local last_size = 0
    print("🔄 Started monitoring CSV file updates...")
    while true do
        local f = io.open(output_csv, "r")
        if f then
            f:seek("end")
            local size = f:seek()  -- Get current file size
            if size > last_size then
                f:seek("set", last_size)  -- Move to where we left off
                for line in f:lines() do
                    print("🔵 CSV Updated: " .. line)
                end
                last_size = size
            end
            f:close()
        end
        os.execute("sleep 1")  -- Wait before checking again
        coroutine.yield()
    end
end

-- Create coroutines for both tasks
local co_json = coroutine.create(monitor_honeypot_logs)
local co_csv = coroutine.create(monitor_csv_file)

-- Main loop: resume both coroutines in a round-robin fashion
while true do
    local ok1, err1 = coroutine.resume(co_json)
    if not ok1 then print("Error in JSON monitor:", err1) end

    local ok2, err2 = coroutine.resume(co_csv)
    if not ok2 then print("Error in CSV monitor:", err2) end

    os.execute("sleep 0.5")  -- Optional short delay between iterations
end
