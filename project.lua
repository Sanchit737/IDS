-- Import LuaSQL MySQL library
local luasql = require("luasql.mysql")
local env = assert(luasql.mysql(), "Error: Failed to initialize LuaSQL MySQL")

-- Connect to MySQL database
local conn = assert(env:connect('Detectors', 'root', 'Sanchit@2004', 'localhost', 3306),
                    "Error: Failed to connect to MySQL database")

math.randomseed(os.time())

-- Ensure the database tables exist
conn:execute([[CREATE TABLE IF NOT EXISTS self_set (
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

conn:execute([[CREATE TABLE IF NOT EXISTS random_detector_set (
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

-- Function to generate a random detector
function random_detector()
    return {
        os.date('%Y-%m-%d %H:%M:%S'),  -- timestamp
        "host" .. math.random(1, 100), -- host
        "process" .. math.random(1, 50), -- process
        math.random(1000, 9999), -- pid
        "event" .. math.random(1, 10), -- event
        "user" .. math.random(1, 20), -- username
        "192.168.1." .. math.random(1, 255), -- ip_address
        math.random(1024, 65535), -- port
        "status" .. math.random(1, 5) -- status
    }
end

-- Function to generate a set of random detectors
function generate_detector_set(num_detectors)
    local ds = {}
    for i = 1, num_detectors do
        table.insert(ds, random_detector())
    end
    return ds
end

-- Function to fetch self_set from MySQL database
function fetch_self_set()
    if not conn then
        print("Error: Database connection is closed!")
        return {}
    end
    
    local self_set = {}
    local cursor, err = conn:execute("SELECT timestamp_col, host, process, pid, event, username, ip_address, port, status FROM self_set")
    if not cursor then
        print("Error fetching self_set: ", err)
        return {}
    end
    
    local row = cursor:fetch({}, "a")
    while row do
        table.insert(self_set, {
            row.timestamp_col, row.host, row.process, tonumber(row.pid), row.event, row.username,
            row.ip_address, tonumber(row.port), row.status
        })
        row = cursor:fetch({}, "a")
    end
    cursor:close()
    return self_set
end

-- Function to update self_set in MySQL database
function update_self_set(fds)
    if not conn then
        print("Error: Database connection is closed!")
        return
    end
    
    conn:execute("DELETE FROM self_set")
    
    for _, detector in ipairs(fds) do
        local query = string.format(
            "INSERT INTO self_set (timestamp_col, host, process, pid, event, username, ip_address, port, status) VALUES ('%s', '%s', '%s', %d, '%s', '%s', '%s', %d, '%s')",
            detector[1], detector[2], detector[3], detector[4], detector[5], detector[6], detector[7], detector[8], detector[9]
        )
        conn:execute(query)
    end
end

-- Function to update random_detector_set in MySQL database
function update_random_detector_set(ds)
    if not conn then
        print("Error: Database connection is closed!")
        return
    end
    
    conn:execute("DELETE FROM random_detector_set")
    
    for _, detector in ipairs(ds) do
        local query = string.format(
            "INSERT INTO random_detector_set (timestamp_col, host, process, pid, event, username, ip_address, port, status) VALUES ('%s', '%s', '%s', %d, '%s', '%s', '%s', %d, '%s')",
            detector[1], detector[2], detector[3], detector[4], detector[5], detector[6], detector[7], detector[8], detector[9]
        )
        conn:execute(query)
    end
end

-- Fetch the current self_set from the database
local self_set = fetch_self_set()

-- Generate random_detector_set
local num_detectors = 10
local ds = generate_detector_set(num_detectors)

-- Store random_detector_set in the database
update_random_detector_set(ds)

-- Generate final_detector_set (for now, assuming all are added to self_set)
update_self_set(ds)

-- Print self_set
print("\n📌 Self Set:")
for _, detector in ipairs(self_set) do
    print("{" .. table.concat(detector, ", ") .. "}")
end

-- Print random_detector_set
print("\n🛠 random_detector_set:")
for _, detector in ipairs(ds) do
    print("{" .. table.concat(detector, ", ") .. "}")
end

-- Print final_detector_set
print("\n✅ final_detector_set (Filtered Non-Self):")
for _, detector in ipairs(ds) do
    print("{" .. table.concat(detector, ", ") .. "}")
end

-- Close the database connection after all operations are complete
if conn then
    conn:close()
    env:close()
end
