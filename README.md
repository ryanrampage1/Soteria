# Soteria

Soteria is a gem to integrate Symantec VIP two factor authentication into any application.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'soteria'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install soteria

## Obtaining a certificate

To use Soteria in your project you first need a certificate from [Symantec VIP manager](https://manager.vip.symantec.com).
To obtain a certificate login and go to Account -> Manage VIP Certificates -> Request a Certificate. From there follow 
the directions to create a new certificate. On the download screen select the PKCS#12 format and enter the password you 
would like to use to secure the certificate.

After downloading the PKCS#12 certificate, you must split it into a public and private key. To do so run the following two 
commands.
   
Extract the private key: 
    
    $ openssl pkcs12 -in yourP12File.pfx -nocerts -out privateKey.pem

Extract the public certificate: 

    $ openssl pkcs12 -in yourP12File.pfx -clcerts -nokeys -out publicCert.pem

## Usage

Once the certificate is split, Soteria is easy to use. 

```ruby
# Start by createing a Soteria client 
soteria = soteria = Soteria.new('/Users/user/soteria/lib/publicCert.pem', '/Users/user/soteria/lib/privateKey.pem', 'passwordForKey')

# Register a new user
soteria.create_user('userid', nil)

# Add a credential
soteria.add_credential('userid', 'VSMT123456', CredentialTypes::STANDARD, nil)

# Send a push to that user
soteria.send_push('userid', nil)
# => { success: true, id: 'send_push_request_20161025010101', transaction_id: '3239814823', message: 'Success' }

# Poll for the push response
soteria.poll_for_response('3239814823', 5, 30)
# => { success: true, message: '"Mobile push request approved by user', id: 'poll_push_status_20161025010101' }
```


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ryanrampage1/soteria. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

