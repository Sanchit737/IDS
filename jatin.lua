local luasql = require "luasql.mysql"
local adaptive_ids = {
    log_file = "/var/log/auth.log",
    detection_patterns = {
        "Failed password",
        "invalid user",
        "authentication failure",
        "BREAK-IN ATTEMPT"
    },
    learning_rate = 0.1,
    threshold = 5,
    -- Database configuration
    db_config = {
        host = 'localhost',
        user = os.getenv("DB_user"),
        password = os.getenv("DB_PASS"),
        database = os.getenv("DB_NAME"),
    },
    conn = nil  -- Will hold database connection
}

-- Track event counts per IP
local event_count = {}

-- Initialize database connection
function adaptive_ids:init_db()
    local env = luasql.mysql()
    self.conn = env:connect(
        self.db_config.database,
        self.db_config.user,
        self.db_config.password,
        self.db_config.host
    )
    
    if not self.conn then
        error("Failed to connect to database")
    end
    
    -- Create tables if they don't exist
    self.conn:execute[[
        CREATE TABLE IF NOT EXISTS access_list (
            id INT AUTO_INCREMENT PRIMARY KEY,
            entry VARCHAR(255) NOT NULL UNIQUE,
            list_type ENUM('whitelist', 'blacklist') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ]]
end

-- Check if IP is in whitelist
function adaptive_ids:is_whitelisted(ip)
    local cursor = self.conn:execute(string.format(
        "SELECT 1 FROM access_list WHERE entry = '%s' AND list_type = 'whitelist'",
        self.conn:escape(ip)
    ))
    local exists = cursor and cursor:fetch()
    if cursor then cursor:close() end
    return exists ~= nil
end

-- Block an IP (add to blacklist)
function adaptive_ids:block_ip(ip)
    -- Check if already blocked
    if not self:is_blocked(ip) then
        self.conn:execute(string.format(
            "INSERT INTO access_list (entry, list_type) VALUES ('%s', 'blacklist')",
            self.conn:escape(ip)
        )
    )
    end
end

-- Check if IP is blocked
function adaptive_ids:is_blocked(ip)
    local cursor = self.conn:execute(string.format(
        "SELECT 1 FROM access_list WHERE entry = '%s' AND list_type = 'blacklist'",
        self.conn:escape(ip)
    ))
    local exists = cursor and cursor:fetch()
    if cursor then cursor:close() end
    return exists ~= nil
end

-- Threat detection logic (modified for database)
function adaptive_ids:detect_threats(line)
    local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
    
    if ip then
        -- Check whitelist first
        if self:is_whitelisted(ip) then
            return
        end

        -- Check blocklist
        if self:is_blocked(ip) then
            self:alert("Blocked IP tried to access: " .. ip, line)
            return
        end
    end

    -- Rest of the detection logic remains same
    for _, pattern in ipairs(self.detection_patterns) do
        if line:find(pattern) then
            self:alert("Suspicious activity detected: " .. pattern, line)
            if ip then
                event_count[ip] = (event_count[ip] or 0) + 1
                if event_count[ip] > self.threshold then
                    self:block_ip(ip)
                end
            end
        end
    end
end

-- Initialize log monitoring with database support
function adaptive_ids:monitor_logs()
    -- Initialize database connection
    self:init_db()
    
    local file = io.open(self.log_file, "r")
    if not file then
        error("Failed to open log file: " .. self.log_file)
    end

    -- Seek to end of file for new entries
    file:seek("end")
    
    while true do
        local new_data = file:read("*a")
        if new_data ~= "" then
            self:analyze_entries(new_data)
        end
        os.execute("sleep 1")  -- Adjust sleep time as needed
    end
end

-- Analyze log entries with database integration
function adaptive_ids:analyze_entries(data)
    for line in data:gmatch("[^\r\n]+") do
        -- First check if line contains any interesting patterns
        local should_analyze = false
        for _, pattern in ipairs(self.detection_patterns) do
            if line:find(pattern) then
                should_analyze = true
                break
            end
        end
        
        if should_analyze then
            self:detect_threats(line)
            self:update_models(line)
        end
    end
end

-- Enhanced alert function with database logging
function adaptive_ids:alert(message, data)
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local full_message = string.format("[%s] ALERT: %s - %s", timestamp, message, data or "")
    
    -- Print to console
    print(full_message)
    
    -- Log to database if connection exists
    if self.conn then
        local success, err = pcall(function()
            self.conn:execute(string.format(
                "INSERT INTO alerts (timestamp, message, raw_data) VALUES ('%s', '%s', '%s')",
                self.conn:escape(timestamp),
                self.conn:escape(message),
                self.conn:escape(data or "")
            ))
        end)
        
        if not success then
            print("Failed to log alert to database: " .. (err or "unknown error"))
        end
    end
    
    -- You could add additional alert mechanisms here (email, syslog, etc.)
end

-- Updated model training with database persistence
function adaptive_ids:update_models(line)
    -- Get current event counts from database
    local total_events = 0
    local cursor, err = self.conn:execute("SELECT COUNT(*) as count FROM alerts")
    
    if cursor then
        local row = cursor:fetch({}, "a")
        if row then
            total_events = tonumber(row.count) or 0
        end
        cursor:close()
    else
        print("Failed to get event count from database: " .. (err or "unknown error"))
    end
    
    -- Adjust threshold based on overall activity
    self.threshold = self.threshold * (1 - self.learning_rate) + 
                    (total_events * self.learning_rate) / 10
    
    -- Store the updated threshold in database
    local success, err = pcall(function()
        self.conn:execute(string.format(
            "INSERT INTO system_settings (setting_name, setting_value) VALUES ('threshold', '%f') "..
            "ON DUPLICATE KEY UPDATE setting_value = '%f'",
            self.threshold,
            self.threshold
        ))
    end)
    
    if not success then
        print("Failed to update threshold in database: " .. (err or "unknown error"))
    end
    
    -- Extract features for machine learning (basic example)
    local ip = line:match("(%d+%.%d+%.%d+%.%d+)")
    if ip then
        -- Store event in database for later analysis
        local success, err = pcall(function()
            self.conn:execute(string.format(
                "INSERT INTO events (ip_address, event_time, raw_data) VALUES ('%s', NOW(), '%s')",
                self.conn:escape(ip),
                self.conn:escape(line)
            ))
        end)
        
        if not success then
            print("Failed to log event to database: " .. (err or "unknown error"))
        end
    end
end

-- Initialize database with all required tables
function adaptive_ids:init_db()
    -- Create tables if they don't exist
    self.conn:execute([[
        CREATE TABLE IF NOT EXISTS access_list (
            id INT AUTO_INCREMENT PRIMARY KEY,
            entry VARCHAR(255) NOT NULL UNIQUE,
            list_type ENUM('whitelist', 'blacklist') NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_list_type (list_type),
            INDEX idx_entry (entry)
        )
    ]])
    
    self.conn:execute([[
        CREATE TABLE IF NOT EXISTS alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            timestamp DATETIME NOT NULL,
            message TEXT NOT NULL,
            raw_data TEXT,
            INDEX idx_timestamp (timestamp)
        )
    ]])
    
    self.conn:execute([[
        CREATE TABLE IF NOT EXISTS events (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45),
            event_time DATETIME NOT NULL,
            raw_data TEXT,
            INDEX idx_ip (ip_address),
            INDEX idx_time (event_time)
        )
    ]])
    
    self.conn:execute([[
        CREATE TABLE IF NOT EXISTS system_settings (
            setting_name VARCHAR(64) PRIMARY KEY,
            setting_value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        )
    ]])
    
    -- Load threshold from database if exists
    local cursor = self.conn:execute("SELECT setting_value FROM system_settings WHERE setting_name = 'threshold'")
    if cursor then
        local row = cursor:fetch({}, "a")
        if row and row.setting_value then
            self.threshold = tonumber(row.setting_value) or self.threshold
        end
        cursor:close()
    end
end

-- Initialize and start monitoring
function adaptive_ids:start()
    self:init_db()
    self:monitor_logs()
end

-- Example usage:
adaptive_ids:start()