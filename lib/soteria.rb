module Soteria

  def self.client(cert_file, cert_key_file, password, should_log)
    Client.new(cert_file, cert_key_file, password, should_log)
  end

end

require "soteria/version"
require "soteria/client"