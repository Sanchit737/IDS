-- Import LuaSQL MySQL library
local luasql = require("luasql.mysql")
local env = assert(luasql.mysql(), "Error: Failed to initialize LuaSQL MySQL")

-- Connect to MySQL database
local db_host = os.getenv("DB_HOST")
local db_user = os.getenv("DB_user")
local db_pass = os.getenv("DB_PASS")
local db_name = os.getenv("DB_NAME")
local db_port = os.getenv("DB_PORT")

-- Connect to MySQL database
local conn = assert(env:connect(db_name, db_user, db_pass, db_host, db_port),
                    "Error: Failed to connect to MySQL database")

-- Ensure the database tables exist
conn:execute([[CREATE TABLE IF NOT EXISTS honeyport_logs (
    timestamp_col DATETIME,
    host VARCHAR(50),
    process VARCHAR(50),
    pid INT,
    event VARCHAR(255),
    username VARCHAR(50),
    ip_address VARCHAR(50),
    port INT,
    status VARCHAR(50)
);]])

--[[ 
Assume the Honeyport log file (e.g., /var/log/honeyport.log) contains CSV records 
with the following fields in order:
timestamp, host, process, pid, event, username, ip_address, port, status

Example line:
2025-03-30 14:22:05,controller,ssh,2345,login_attempt,unknown,192.168.1.100,22,failed
--]]

-- Function to fetch logs from Honeyport log file
function fetch_honeyport_logs(filename)
    local logs = {}
    local f = io.open(filename, "r")
    if not f then
        print("Error: Unable to open Honeyport log file: " .. filename)
        return logs
    end

    for line in f:lines() do
        -- Parse CSV fields (assuming no commas inside fields)
        local timestamp, host, process, pid, event, username, ip_address, port, status = 
            line:match("([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)")
        if timestamp then
            table.insert(logs, {
                timestamp,
                host,
                process,
                tonumber(pid) or 0,
                event,
                username,
                ip_address,
                tonumber(port) or 0,
                status
            })
        else
            print("Warning: Skipping unparseable line: " .. line)
        end
    end
    f:close()
    return logs
end

-- Function to update honeyport_logs table in MySQL database
function update_honeyport_logs(logs)
    if not conn then
        print("Error: Database connection is closed!")
        return
    end

    -- Optionally clear the table before inserting new records
    conn:execute("DELETE FROM honeyport_logs")
    
    for _, log in ipairs(logs) do
        local query = string.format(
            "INSERT INTO honeyport_logs (timestamp_col, host, process, pid, event, username, ip_address, port, status) VALUES ('%s', '%s', '%s', %d, '%s', '%s', '%s', %d, '%s')",
            log[1], log[2], log[3], log[4], log[5], log[6], log[7], log[8], log[9]
        )
        local res, err = conn:execute(query)
        if not res then
            print("Error executing query: ", err)
        end
    end
end

-- Main processing:
-- Define the Honeyport log file path (adjust as needed)
local honeyport_log_file = "/home/cowrie/cowrie/var/log/cowrie/"

-- Fetch logs from the Honeyport log file
local honeyport_logs = fetch_honeyport_logs(honeyport_log_file)

-- Update the MySQL table with the fetched logs
update_honeyport_logs(honeyport_logs)

-- Print the logs that were fetched and processed
print("\n📜 Honeyport Logs:")
for _, log in ipairs(honeyport_logs) do
    print("{" .. table.concat(log, ", ") .. "}")
end

-- Close the database connection after all operations are complete
if conn then
    conn:close()
    env:close()
end
