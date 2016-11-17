require 'spec_helper'
require 'savon/mock/spec_helper'

describe Soteria::Push do

  include Savon::SpecHelper

  before :all do
    savon.mock!

    @push = Soteria::Push.new

    auth_client_wsdl = File.read('spec/fixtures/wsdl/vipuserservices-auth-1.7.wsdl')
    @auth_client = Savon.client(wsdl: auth_client_wsdl)

    query_client_wsdl = File.read('spec/fixtures/wsdl/vipuserservices-query-1.7.wsdl')
    @query_client = Savon.client(wsdl: query_client_wsdl)
  end

  after :all do
    savon.unmock!
  end

  it 'sends the push with success' do
    body = File.read('spec/fixtures/push/authenticate_with_push_response.xml')
    savon.expects(:authenticate_user_with_push).with(message: :any).returns(body)
    res = @push.send_push(@auth_client, '', nil)

    expect(res[:id]).to eq 'send_push_request_20161021152920'
    expect(res[:success]).to eq true
    expect(res[:transaction_id]).to eq '8d70d18461cc9093'
    expect(res[:message]).to eq 'Mobile push request sent'

  end

  it 'sends the push with failure' do
    body = File.read('spec/fixtures/push/authenticate_with_push_error.xml')
    savon.expects(:authenticate_user_with_push).with(message: :any).returns(body)
    res = @push.send_push(@auth_client, '', nil)

    expect(res[:id]).to eq 'send_push_request_20161021152920'
    expect(res[:success]).to eq false
    expect(res[:transaction_id]).to eq nil
    expect(res[:message]).to eq 'User does not exist.'

  end

  it 'polls for a response' do

  end

  context 'with no additional options passed' do

    it 'forms the request body with only required fields' do
      result_hash = @push.get_push_request_body('test_user', nil)
      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'test_user',
          'vip:pushAuthData': ''
      }

      expect(result_hash).to match expected_hash
    end

  end

  context 'with title and message passed' do

    it 'forms the request body with required fields and title and message' do
      options = {title: 'push title', message: 'this is a test push'}
      result_hash = @push.get_push_request_body('test_user', options)
      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'test_user',
          'vip:pushAuthData': {
              'vip:displayParameters': [
                  {'vip:Key': 'display.message.title', 'vip:Value': options[:title]},
                  {'vip:Key': 'display.message.text', 'vip:Value': options[:message]}
              ]
          }
      }

      expect(result_hash).to match expected_hash
    end

  end

  context 'with a timeout and no title or message' do

    it 'forms the request body with required fields and timeout' do
      options = {time_out: 120}

      result_hash = @push.get_push_request_body('test_user', options)
      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'test_user',
          'vip:pushAuthData': {
              'vip:displayParameters': [],
              'vip:requestParameters':
                  {
                      'vip:Key': 'request.timeout',
                      'vip:Value': options[:time_out]
                  }
          }
      }

      expect(result_hash).to match expected_hash
    end

  end

  context 'with a timeout and a title and a message' do

    it 'forms the request body with required fields along with the title, message and timeout' do
      options = {time_out: 120, title: 'push title', message: 'this is a test push'}

      result_hash = @push.get_push_request_body('test_user', options)
      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'test_user',
          'vip:pushAuthData': {
              'vip:displayParameters': [
                  {'vip:Key': 'display.message.title', 'vip:Value': options[:title]},
                  {'vip:Key': 'display.message.text', 'vip:Value': options[:message]}
              ],
              'vip:requestParameters':
                  {
                      'vip:Key': 'request.timeout',
                      'vip:Value': options[:time_out]
                  }
          }
      }

      expect(result_hash).to match expected_hash
    end

  end

end

