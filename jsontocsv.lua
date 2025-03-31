-- local json = require("dkjson")
-- local luasql = require("luasql.mysql")
-- local env = assert(luasql.mysql(), "Error: Failed to initialize LuaSQL MySQL")

-- -- Database credentials
-- local db_host = os.getenv("DB_HOST")
-- local db_user = os.getenv("DB_USER")
-- local db_pass = os.getenv("DB_PASS")
-- local db_name = os.getenv("DB_NAME")
-- local db_port = os.getenv("DB_PORT")

-- -- Connect to MySQL database
-- local conn = assert(env:connect(db_name, db_user, db_pass, db_host, db_port),
--                     "Error: Failed to connect to MySQL database")

-- -- Ensure the database table exists for blocked attempts
-- -- conn:execute([[CREATE TABLE IF NOT EXISTS blocked_attempts (
-- --     id INT AUTO_INCREMENT PRIMARY KEY,
-- --     src_ip VARCHAR(50),
-- --     dst_port INT,
-- --     attempts INT
-- -- );]])

-- -- File paths
-- local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
-- local output_csv = "/home/user/honeypot/honeypot_logs.csv"
-- local log_output_file = "/home/user/honeypot/processed_logs.log"

-- -- Track login attempts per IP within 10 minutes
-- local login_attempts = {}

-- local function iso8601_to_unix(ts)
--     if ts == "" then return nil end
    
--     -- Extract date-time components (ignoring microseconds/timezone)
--     local year, month, day, hour, min, sec = ts:match(
--         "^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)"
--     )
--     if not year then return nil end
    
--     -- Create time table (assumes UTC timezone)
--     local time_table = {
--         year = tonumber(year),
--         month = tonumber(month),
--         day = tonumber(day),
--         hour = tonumber(hour),
--         min = tonumber(min),
--         sec = tonumber(sec),
--         isdst = false
--     }
    
--     -- Convert to Unix timestamp with timezone adjustment
--     local success, unix_time = pcall(os.time, time_table)
--     return success and unix_time or nil
-- end

-- -- Function to process and append a single log line
-- local function process_log_line(line)
--     local log_entry, _, err = json.decode(line)
--     if log_entry then
--         local timestamp = log_entry.timestamp or ""
--         local src_ip = log_entry.src_ip or ""
--         local eventid = log_entry.eventid or ""
--         local username = log_entry.username or ""
--         local sensor = log_entry.sensor or ""
--         local dst_port = log_entry.dst_port or ""
--         local password = log_entry.password or ""
--         local current_time = iso8601_to_unix(timestamp) or os.time()

--         -- Append to CSV file
--         local csv_f = io.open(output_csv, "a")
--         if csv_f then
--             csv_f:write(table.concat({current_time, src_ip, eventid, username, sensor, dst_port, password}, ",") .. "\n")
--             csv_f:close()
--         else
--             print("Error: Unable to open CSV file: " .. output_csv)
--         end

--         -- Append to log file
--         local log_f = io.open(log_output_file, "a")
--         if log_f then
--             log_f:write(string.format("{%s, %s, %s, %s, %s, %s, %s}\n", current_time, src_ip, eventid, username, sensor, dst_port, password))
--             log_f:close()
--         else
--             print("Error: Unable to open log file: " .. log_output_file)
--         end

--         print("🟢 New Log Processed: {" .. table.concat({current_time, src_ip, eventid, username, sensor, dst_port, password}, ", ") .. "}")

--         -- Track login attempts per IP and port
--         local key = src_ip .. ":" .. dst_port

--         if not login_attempts[key] then
--             login_attempts[key] = {count = 1, first_attempt = current_time}
--         else
--             local attempt_data = login_attempts[key]
--             if (current_time - attempt_data.first_attempt) <= 600 then  -- 600 seconds = 10 minutes
--                 attempt_data.count = attempt_data.count + 1
--             else
--                 login_attempts[key] = {count = 1, first_attempt = current_time}
--             end
--         end

--         -- If more than 3 attempts in 10 minutes, classify as an attack
--         if login_attempts[key].count >= 4 then
--             print("🚨 Alert: Multiple failed login attempts detected from " .. src_ip .. " on port " .. dst_port)
            
--             -- Block IP using iptables
--             local block_cmd = string.format("iptables -A INPUT -s %s -j DROP", src_ip)
--             local block_status = os.execute(block_cmd)
            
--             if block_status then
--                 print("🔒 IP " .. src_ip .. " blocked via iptables")
--             else
--                 print("❌ Failed to block IP " .. src_ip)
--             end
            
--             -- Insert into the database if not already present
--             local check_query = string.format("SELECT * FROM self_set WHERE source_ip = '%s' AND destination_port = %d",
--             src_ip, tonumber(dst_port) or 0)

--             local cursor, err = conn:execute(check_query)

--             local cursor, err = conn:execute(check_query)
            
--             if not cursor then
--                 print("Error checking existing entry:", err)
--             else
--                 local row = cursor:fetch({}, "a")
--                 if not row then
--                     local query = string.format("INSERT INTO self_set (source_ip, destination_port) VALUES ('%s', %d)", src_ip, tonumber(dst_port) or 0)
--                     local res, err = conn:execute(query)
--                     if not res then
--                         print("Error inserting blocked attempt:", err)
--                     else
--                         print("✅ Blocked attempt stored in database!")
--                     end
--                 else
--                     print("ℹ️ Entry already exists in database")
--                 end
--             end
--         else
--             print("Warning: Skipping unparseable line: " .. (err or "Unknown error"))
--         end
--     end
-- end

-- -- Coroutine to monitor the honeypot JSON log file in real-time
-- function monitor_honeypot_logs()
--     local f = io.open(honeypot_log_file, "r")
--     if not f then
--         print("Error: Unable to open honeypot log file: " .. honeypot_log_file)
--         return
--     end

--     f:seek("end")  -- Move to the end of the file
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

-------------------
-- Configuration --
-------------------
local config = {
    db = {
        host = os.getenv("DB_HOST"),
        user = os.getenv("DB_user"),
        pass = os.getenv("DB_PASS"),
        name = os.getenv("DB_NAME"),
        port = os.getenv("DB_PORT")
    },
    paths = {
        honeypot_log = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json",
        output_csv = "/home/user/honeypot/honeypot_logs.csv",
        processed_logs = "/home/user/honeypot/processed_logs.log"
    },
    security = {
        attack_threshold = 3,      -- 3 failed attempts
        time_window = 600,         -- 10 minutes (seconds)
        iptables_chain = "INPUT",
        persist_rules = true
    },
    buffers = {
        file_write = 4096,         -- 4KB buffer
        coroutine_delay = 0.5      -- Seconds
    }
}

-------------------------
-- Database Connection --
-------------------------
local env = assert(luasql.mysql(), "Failed to initialize MySQL environment")
local conn = assert(env:connect(config.db.name, config.db.user, config.db.pass, 
                              config.db.host, config.db.port), "DB connection failed")

-- Create tables if not exists
-- conn:execute([[
--     CREATE TABLE IF NOT EXISTS blocked_attempts (
--         id INT AUTO_INCREMENT PRIMARY KEY,
--         source_ip VARCHAR(45) NOT NULL,
--         destination_port INT NOT NULL,
--         first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
--         last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
--         attempts INT DEFAULT 1,
--         UNIQUE KEY unique_entry (source_ip, destination_port)
-- )]])

-----------------------
-- Helper Functions --
-----------------------
local function log_message(level, message)
    local entry = string.format("[%s] [%s] %s",
        os.date("%Y-%m-%dT%H:%M:%SZ"),
        level:upper(),
        message
    )
    print(entry)
end

local function is_valid_ip(ip)
    return ip and ip:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end

local function sanitize_input(str)
    return conn:escape(tostring(str))
end

local function iso8601_to_unix(ts)
    if ts == "" then return nil end
    
    local pattern = "^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)"
    local year, month, day, hour, min, sec = ts:match(pattern)
    if not year then return nil end
    
    local time_table = {
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = tonumber(hour),
        min = tonumber(min),
        sec = tonumber(sec),
        isdst = false
    }
    
    local success, unix_time = pcall(os.time, time_table)
    return success and unix_time or nil
end

local function block_ip(src_ip)
    if not is_valid_ip(src_ip) then
        log_message("error", "Invalid IP format: " .. tostring(src_ip))
        return false
    end

    -- Check existing iptables rule
    local check_cmd = string.format("iptables -C %s -s %s -j DROP 2>/dev/null",
                                   config.security.iptables_chain, src_ip)
    if os.execute(check_cmd) then
        log_message("info", "IP " .. src_ip .. " already blocked")
        return true
    end

    -- Add new blocking rule
    local block_cmd = string.format("iptables -I %s 1 -s %s -j DROP",
                                   config.security.iptables_chain, src_ip)
    local success = os.execute(block_cmd)
    
    if success then
        if config.security.persist_rules then
            os.execute("iptables-save > /etc/iptables/rules.v4")
        end
        log_message("security", "Blocked IP: " .. src_ip)
        return true
    else
        log_message("error", "Failed to block IP: " .. src_ip)
        return false
    end
end

local function update_database(src_ip, dst_port, event_id)
    local sanitized_ip = sanitize_input(src_ip)
    local port = tonumber(dst_port) or 0

    local query = string.format([[
        INSERT INTO self_set 
        (source_ip, destination_port, event_id)
        VALUES ('%s', %d, '%s')]],
        sanitized_ip, port, event_id)

    local success, err = pcall(conn.execute, conn, query)
    if not success then
        log_message("error", "Database update failed: " .. tostring(err))
        return false
    end
    return true
end

-------------------------
-- Core Functionality --
-------------------------
local event_attempts = {}

local function process_log_line(line)
    local log_entry, pos, err = json.decode(line)
    if not log_entry then
        log_message("warning", "Failed to parse log: " .. tostring(err))
        return
    end

    -- Extract fields with sanitization
    local fields = {
        timestamp = iso8601_to_unix(log_entry.timestamp or "") or os.time(),
        src_ip = sanitize_input(log_entry.src_ip or ""),
        eventid = sanitize_input(log_entry.eventid or ""),
        username = sanitize_input(log_entry.username or ""),
        sensor = sanitize_input(log_entry.sensor or ""),
        dst_port = tonumber(log_entry.dst_port) or 0,
        password = sanitize_input(log_entry.password or "")
    }

    -- Write to CSV
    local csv_line = table.concat({
        fields.timestamp,
        fields.src_ip,
        fields.eventid,
        fields.username,
        fields.sensor,
        fields.dst_port,
        fields.password
    }, ",")

    local csv_f = io.open(config.paths.output_csv, "a")
    if csv_f then
        csv_f:setvbuf("full", config.buffers.file_write)
        csv_f:write(csv_line .. "\n")
        csv_f:close()
    else
        log_message("error", "Failed to open CSV file")
    end

    -- Update processed logs
    local log_f = io.open(config.paths.processed_logs, "a")
    if log_f then
        log_f:setvbuf("full", config.buffers.file_write)
        log_f:write(string.format("{%s}\n", csv_line))
        log_f:close()
    end

      -- Track event attempts based on src_ip, dst_port, and eventid
      local key = fields.src_ip .. ":" .. tostring(fields.dst_port) .. ":" .. fields.eventid
      local current_time = fields.timestamp
  
      if not event_attempts[key] then
          event_attempts[key] = {
              count = 1,
              first_attempt = current_time,
              blocked = false
          }
      else
          local attempt = event_attempts[key]
          if (current_time - attempt.first_attempt) <= config.security.time_window then
              attempt.count = attempt.count + 1
          else
              -- Reset counter if outside time window
              event_attempts[key] = {
                  count = 1,
                  first_attempt = current_time,
                  blocked = false
              }
          end
      end

    
    -- Check attack threshold
    local attempt_data = event_attempts[key]
    if not attempt_data.blocked and 
       attempt_data.count >= config.security.attack_threshold then
        
        log_message("alert", string.format(
            "Attack detected: %s:%d (%s) - %d attempts",
            fields.src_ip, fields.dst_port, fields.eventid, attempt_data.count
        ))

              -- Block IP and update database
              if block_ip(fields.src_ip) and update_database(fields.src_ip, fields.dst_port, fields.eventid) then
                attempt_data.blocked = true
                log_message("security", string.format(
                    "Successfully blocked %s for repeated %s events on port %d",
                    fields.src_ip, fields.eventid, fields.dst_port
                ))
            end
        end
    end
---------------------
-- File Monitoring --
---------------------
local function file_monitor(file_path, processor)
    local f = io.open(file_path, "r")
    if not f then
        log_message("error", "Cannot open file: " .. file_path)
        return nil
    end

    f:seek("end")
    return function()
        while true do
            local line = f:read("*l")
            if line then
                processor(line)
            else
                os.execute("sleep 1")
            end
            coroutine.yield()
        end
    end
end

-----------------
-- Main Logic --
-----------------
local function cleanup()
    log_message("info", "Shutting down...")

    -- Close database connections
    if conn and conn:ping() then
        conn:close()
    end
    if env then
        env:close()
    end
    
    -- Remove temporary files
    os.remove("/tmp/honeypot_cleanup.flag")
    
    log_message("info", "Cleanup completed")
    os.exit(0)
end

-- POSIX-compliant signal handling
local has_posix, posix = pcall(require, "posix")
local has_signal, signal = pcall(require, "posix.signal")

if has_posix and has_signal then
    signal.signal(signal.SIGINT, function()
        log_message("warning", "Received SIGINT - initiating shutdown")
        cleanup()
    end)
    
    signal.signal(signal.SIGTERM, function()
        log_message("warning", "Received SIGTERM - initiating shutdown")
        cleanup()
    end)
else
    log_message("warning", "POSIX module not found - using file-based signal handling")
    local co_signal = coroutine.create(function()
        local signal_file = "/tmp/honeypot_cleanup.flag"
        os.execute("touch " .. signal_file)
        
        while true do
            local f = io.open(signal_file, "r")
            if f then
                local modified = f:seek("end") > 0
                f:close()
                if modified then
                    cleanup()
                end
            end
            os.execute("sleep 1")
            coroutine.yield()
        end
    end)
    coroutine.resume(co_signal)
end

-- Start monitoring
local monitor_honeypot = file_monitor(config.paths.honeypot_log, process_log_line)
local co_json = coroutine.create(monitor_honeypot)

local function monitor_csv()
    local last_size = 0
    while true do
        local f = io.open(config.paths.output_csv, "r")
        if f then
            f:seek("end")
            local size = f:seek()
            if size > last_size then
                f:seek("set", last_size)
                for line in f:lines() do
                    log_message("info", "CSV Update: " .. line)
                end
                last_size = size
            end
            f:close()
        end
        os.execute("sleep 1")
        coroutine.yield()
    end
end
local co_csv = coroutine.create(monitor_csv)

-- Main loop
log_message("info", "Starting honeypot monitoring system")
while true do
    local ok, err = coroutine.resume(co_json)
    if not ok then
        log_message("error", "JSON monitor failed: " .. tostring(err))
    end

    ok, err = coroutine.resume(co_csv)
    if not ok then
        log_message("error", "CSV monitor failed: " .. tostring(err))
    end

    os.execute("sleep " .. config.buffers.coroutine_delay)
end