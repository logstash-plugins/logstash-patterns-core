module LogStash
  module Patterns
    module Core
      extend self

      def path
        ::File.expand_path('../../../patterns/legacy', ::File.dirname(__FILE__))
      end

    end
  end
end
