require_relative '../lib/soteria/user'
require 'spec_helper'
require 'savon/mock/spec_helper'
require 'date'

describe Soteria::User do
  # include the helper module
  include Savon::SpecHelper

  before :all do
    savon.mock!

    @user = Soteria::User.new
    @mgmt_client = Savon.client(wsdl: File.read("spec/fixtures/wsdl/vipuserservices-mgmt-1.7.wsdl"))
    @query_client = Savon.client(wsdl: File.read("spec/fixtures/wsdl/vipuserservices-query-1.7.wsdl"))
  end

  after :all do
    savon.unmock!
  end
  context 'makes a hash with the right return values' do
    it 'makes a hash when the call succeed' do
      h = {status: '0000', status_message: 'Success', request_id: 'test1234'}
      res = @user.get_return_hash(h)
      expect(res[:success]).to eq true
      expect(res[:message]).to eq 'Success'
      expect(res[:id]).to eq 'test1234'
    end

    it 'makes a hash when the call has errors' do
      h = {status: '6002', status_message: 'User already exists.', request_id: 'test1234'}
      res = @user.get_return_hash(h)
      expect(res[:success]).to eq false
      expect(res[:message]).to eq 'User already exists.'
      expect(res[:id]).to eq 'test1234'
    end
  end

  it 'creates a user' do
    body = File.read("spec/fixtures/user/create_user_response.xml")
    savon.expects(:create_user).with(message: :any).returns(body)
    res = @user.create(@mgmt_client, '', nil)

    expect(res[:success]).to be true
    expect(res[:message]).to eq 'Success'
    expect(res[:id]).to eq 'test1234'
  end

  it 'deletes a user' do
    body = File.read("spec/fixtures/user/delete_user_response.xml")
    savon.expects(:delete_user).with(message: :any).returns(body)
    res = @user.delete(@mgmt_client, '')

    expect(res[:success]).to be true
    expect(res[:message]).to eq 'Success'
    expect(res[:id]).to eq 'test1234'
  end

  it 'adds a credential to a user' do

    body = File.read("spec/fixtures/user/add_credential_response.xml")
    savon.expects(:add_credential).with(message: :any).returns(body)
    res = @user.add_credential(@mgmt_client, '', '', '', nil)

    expect(res[:success]).to be true
    expect(res[:message]).to eq 'Success'
    expect(res[:id]).to eq '4ACCDv2rtj'

  end

  context 'gets the request body for adding a credential' do

    it 'gets the body with no options' do
      result_hash = @user.get_add_credential_message('user1', 'credential', 'STANDARD_OTP', nil)

      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'user1',
          'vip:credentialDetail': {
              'vip:credentialId': 'credential',
              'vip:credentialType': 'STANDARD_OTP'
          }
      }

      expect(result_hash).to match expected_hash

    end

    it 'gets the body with a friendly name and otp' do

      options = {name: 'testCredential', otp: '123456'}
      result_hash = @user.get_add_credential_message('user1', 'credential', 'STANDARD_OTP', options)

      # TODO: this is a hack until we mock the utilities class to set the request id
      result_hash[:'vip:requestId'] = nil

      expected_hash = {
          'vip:requestId': nil,
          'vip:userId': 'user1',
          'vip:otpAuthData': {
              'vip:otp': '123456'
          },
          'vip:credentialDetail': {
              'vip:credentialId': 'credential',
              'vip:credentialType': 'STANDARD_OTP',
              'vip:friendlyName': 'testCredential'
          }
      }

      expect(result_hash).to match expected_hash

    end

    it 'removes a credential from a user' do

      body = File.read("spec/fixtures/user/remove_credential_response.xml")
      savon.expects(:remove_credential).with(message: :any).returns(body)

      result_hash = @user.remove_credential(@mgmt_client, '', '', '')

      expected_hash =  {
          success: true,
          message: 'Success',
          id: '1234abcd'
      }

      expect(result_hash).to match expected_hash

    end

    it 'updates a user' do
      body = File.read("spec/fixtures/user/update_user_response.xml")
      savon.expects(:update_user).with(message: :any).returns(body)

      result_hash = @user.update_user(@mgmt_client, '', nil)

      expected_hash =  {
          success: true,
          message: 'Success',
          id: '123456'
      }

      expect(result_hash).to match expected_hash
    end

    it 'clears a users pin' do
      body = File.read("spec/fixtures/user/clear_user_pin_response.xml")
      savon.expects(:clear_user_pin).with(message: :any).returns(body)

      result_hash = @user.clear_user_pin(@mgmt_client, '')

      expected_hash =  {
          success: true,
          message: 'Success',
          id: '123edabc'
      }

      expect(result_hash).to match expected_hash
    end

    it 'sets temporary password attributes' do
      body = File.read("spec/fixtures/user/set_temp_pass_attr_response.xml")
      savon.expects(:set_temporary_password_attributes).with(message: :any).returns(body)

      result_hash = @user.set_temp_pass_attr(@mgmt_client, '', nil)

      expected_hash =  {
          success: true,
          message: 'Success',
          id: 'KSOfaUFH52'
      }

      expect(result_hash).to match expected_hash
    end

    it 'gets temporary password attributes' do
      body = File.read("spec/fixtures/user/get_temp_pass_attr_response.xml")
      savon.expects(:get_temporary_password_attributes).with(message: :any).returns(body)

      result_hash = @user.get_temp_pass_attr(@query_client, '')

      expected_hash =  {
          success: true,
          message: 'Success',
          id: '123456',
          oneTime: true,
          expiration: Date.parse('2011-04-08T08:17:50.000Z')
      }

      expect(result_hash).to match expected_hash
    end

    it 'sets a temporary password' do
        body = File.read("spec/fixtures/user/set_temp_pass_response.xml")
        savon.expects(:set_temporary_password).with(message: :any).returns(body)

        result_hash = @user.set_temp_password(@mgmt_client, '', '', nil)

        expected_hash =  {
            success: true,
            message: 'Success',
            id: '1234abcd',
            password: '321345'
        }

        expect(result_hash).to match expected_hash
    end

    it 'clears a temporary password' do
        body = File.read("spec/fixtures/user/clear_temp_password_response.xml")
        savon.expects(:clear_temporary_password).with(message: :any).returns(body)

        result_hash = @user.clear_temp_pass(@mgmt_client, '')

        expected_hash =  {
            success: true,
            message: 'Success',
            id: '0HaNgjq7z9'
        }

        expect(result_hash).to match expected_hash
    end

    it 'updates a users credential' do

      body = File.read("spec/fixtures/user/update_credential_response.xml")
      savon.expects(:update_credential).with(message: :any).returns(body)

      result_hash = @user.update_credential(@mgmt_client, '', '', '', '')

      expected_hash =  {
          success: true,
          message: 'Success',
          id: '6dtFnd3qpK'
      }

      expect(result_hash).to match expected_hash

    end

  end

end
