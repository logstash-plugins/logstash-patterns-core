# encoding: utf-8
def test_message(pattern_name, sample_message)
  describe pattern_name do
    before(:each) { grok.register; grok.filter(event) }
    let(:grok) { LogStash::Filters::Grok.new("match" => ["message", "%{#{subject}}"]) }
    let(:event) { LogStash::Event.new("message" => sample_message) }
    it "matches a sample line" do
      expect(event.to_hash).to_not include("tags")
    end
  end
end
