lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'soteria/version'

Gem::Specification.new do |spec|
  spec.name          = "soteria"
  spec.version       = Soteria::VERSION
  spec.authors       = ["Ryan Casler"]
  spec.email         = ['ryan.casler12@gmail.com']

  spec.summary       = 'Symantec VIP'
  spec.description   = 'A gem for authentication with Symantec VIP Services.'
  spec.homepage      = "https://github.com/ryanrampage1/soteria"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_dependency             'savon', '~> 2.11', '>= 2.11.0'

  spec.add_development_dependency "bundler", "~> 1.13"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
