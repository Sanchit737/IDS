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

-- Initialize and start monitoring
function adaptive_ids:start()
    self:init_db()
    self:monitor_logs()
end

-- Example usage:
adaptive_ids:start()