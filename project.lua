-- Import LuaSQL MySQL library
local luasql = require("luasql.mysql")
local env = assert(luasql.mysql(), "Error: Failed to initialize LuaSQL MySQL")

-- Retrieve database credentials from environment variables
local db_host = os.getenv("DB_HOST")
local db_user = os.getenv("DB_user")
local db_pass = os.getenv("DB_PASS")
local db_name = os.getenv("DB_NAME")
local db_port = os.getenv("DB_PORT")

-- Connect to MySQL database
local conn = assert(env:connect(db_name, db_user, db_pass, db_host, db_port),
                    "Error: Failed to connect to MySQL database")

-- Ensure the database table exists
conn:execute([[CREATE TABLE IF NOT EXISTS honeypot_logs (
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

-- Function to fetch logs from honeypot log file
function fetch_honeypot_logs(filename)
    local logs = {}
    local f = io.open(filename, "r")
    if not f then
        print("Error: Unable to open honeypot log file: " .. filename)
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

-- Function to update honeypot_logs table in MySQL database
function update_honeypot_logs(logs)
    if not conn then
        print("Error: Database connection is closed!")
        return
    end

    -- Optionally clear the table before inserting new records
    conn:execute("DELETE FROM honeypot_logs")
    
    for _, log in ipairs(logs) do
        local query = string.format(
            "INSERT INTO honeypot_logs (timestamp_col, host, process, pid, event, username, ip_address, port, status) VALUES ('%s', '%s', '%s', %d, '%s', '%s', '%s', %d, '%s')",
            log[1], log[2], log[3], log[4], log[5], log[6], log[7], log[8], log[9]
        )
        local res, err = conn:execute(query)
        if not res then
            print("Error executing query: ", err)
        end
    end
end

-- Function to export MySQL data to a CSV file using CSV Kit
function export_logs_to_csv(output_csv)
    -- MySQL query to export logs
    local csv_query = string.format(
        "SELECT * FROM honeypot_logs INTO OUTFILE '%s' FIELDS TERMINATED BY ',' ENCLOSED BY '\"' LINES TERMINATED BY '\n'",
        output_csv
    )
    
    local res, err = conn:execute(csv_query)

    if not res then
        print("Error exporting logs to CSV:", err)
    else
        print("✅ Logs successfully exported to CSV:", output_csv)
    end
end

-- Main processing:
-- Define log file path & output CSV file
local honeypot_log_file = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
local output_csv = "/home/user/honeypot/honeypot_logs.csv"  -- Adjust path

-- Fetch logs from the honeypot log file
local honeypot_logs = fetch_honeypot_logs(honeypot_log_file)

-- Update the MySQL table with the fetched logs
update_honeypot_logs(honeypot_logs)

-- Export logs to CSV using CSV Kit
export_logs_to_csv(output_csv)

-- Print the logs that were fetched and processed
print("\n📜 honeypot Logs:")
for _, log in ipairs(honeypot_logs) do
    print("{" .. table.concat(log, ", ") .. "}")
end

-- Close the database connection after all operations are complete
if conn then
    conn:close()
    env:close()
end
