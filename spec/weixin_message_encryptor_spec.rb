require 'spec_helper'

RSpec.describe WeixinMessageEncryptor do

  let(:encoding_aes_key) { 'djd2WiYRvgqbCUwzeFojrmAP6uhoA8qZXDrwYQJ6fUM' }
  let(:sign_token) { 'ZFzVtXmLfsNRxGPoYcfVH' }
  let(:app_id) { 'tjc29Q32328e98FnN6' }

  let(:encryptor) { WeixinMessageEncryptor.new(encoding_aes_key: encoding_aes_key, sign_token: sign_token, app_id: app_id) }

  before do
    Timecop.freeze(Time.parse('2017-08-28 10:00:00+0800'))
  end

  after do
    Timecop.return
  end

  context '#encrypt' do

    let(:expected_encrypted) do
      <<XML
<xml>
<Encrypt><![CDATA[od2fsaJOhtlyv5DB3LVSmnUj+NyJhjzXp3rGInQJ2TnXMAGmZk5Xbe78X9KlQbAh9EUZtpI6sm3r+HKau1gkUw==]]></Encrypt>
<MsgSignature><![CDATA[c259384cc497c5e89770524a8ff669274df330da]]></MsgSignature>
<TimeStamp>1503885600</TimeStamp>
<Nonce><![CDATA[d8a578a6e9daf581]]></Nonce>
</xml>
XML
    end

    it 'encrypts message with signature' do
      expect(SecureRandom).to receive(:hex).twice.with(8).and_return('d8a578a6e9daf582', 'd8a578a6e9daf581')

      encrypted = encryptor.encrypt 'plain text message'

      expect(encrypted).to eq expected_encrypted
    end

  end

  context '#decrypt' do

    let(:payload) do
      {
        'xml' => {
          'ToUserName' => 'wx23961585be2ea4d6',
          'Encrypt' => 'zg4zDMF/J0Odl0E4WEzgugu/aq/GS5ASYG3DflkhWe+HYcoGSI1hWlN1HP2mzBzeQ5pAkNXMUqizkqCwHW++Jv7w3ZL+gyZ1DdLTBU6azKSi/3RMDLJIVgmz2vGoLptAoWzwWZTMNIPkKcUC1CwfXnMbHJjyHRDqRedk0syy7BblPE5At+WZKtQAXb44Zt3rkhS8abhPPFH43wAutMn9JUhNmHXx9qC3cXVSnDe6OwOx7yfxeFBIpAJfxdT66uGpFOgRYQJHq//iId8Ky3f39dahLQLa87WiwMD3P3YCsw7zMT1JAokAGBCl+iynK1peeZnpqAvp7BkfdsB7oMBaUU4cvL3lcBGLhZ98mR4Lev7ygWyoqh+S8t0k09SY85aYfWBNwEYImegG0xqpnZsHHmjhCcK7Yvt0rYIuE9AVO2U=',
          'AgentID' => '25'
        },
        'msg_signature' => 'c1ec582f70ed50d147322810aa28620d8cd7e965',
        'timestamp' => '1486718199',
        'nonce' => '1354621423',
        'corp_id' => 'tjc29Q32328e98FnN6'
      }
    end

    let(:expected_decrypted) do
      <<XML
<xml><ToUserName><![CDATA[wx23961585be2ea4d6]]></ToUserName>
<FromUserName><![CDATA[wjj]]></FromUserName>
<CreateTime>1486718199</CreateTime>
<MsgType><![CDATA[event]]></MsgType>
<AgentID>25</AgentID>
<Event><![CDATA[subscribe]]></Event>
<EventKey><![CDATA[]]></EventKey>
</xml>
XML
    end

    it 'decrypts message with signature' do
      decrypted, account_id, signature = encryptor.decrypt payload

      expect(decrypted).to eq expected_decrypted.strip
      expect(account_id).to eq 'tjc29Q32328e98FnN6'
      expect(signature).to eq 'c1ec582f70ed50d147322810aa28620d8cd7e965'
    end

  end

end
