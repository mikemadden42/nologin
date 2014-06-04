#!/usr/bin/env ruby

File.open('/etc/passwd').each do |line|
  line.chomp!
  account_data = line.split ':'
  puts account_data[0] if account_data[6] == '/sbin/nologin'
end
