# encoding: utf-8
def grok(pattern_name, sample_message, fields = {})
  describe pattern_name do
    before(:each) { grok_obj.register; grok_obj.filter(event) }
    let(:grok_obj) { LogStash::Filters::Grok.new("match" => ["message", "%{#{pattern_name}}"]) }
    let(:event) { LogStash::Event.new("message" => sample_message) }

    context "testing line \"#{sample_message}\"" do
      it "matches" do
        expect(event.to_hash).to_not include("tags")
      end

      if !fields.empty?
        it "has expected fields \"#{fields.inspect}\"" do
          expect(event.to_hash).to include(fields)
        end
      end
    end
  end
end
