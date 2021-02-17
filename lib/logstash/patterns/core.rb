module LogStash
  module Patterns
    module Core
      extend self

      BASE_PATH = ::File.expand_path('../../../patterns', ::File.dirname(__FILE__))
      private_constant :BASE_PATH

      def path(type = 'legacy')
        case type = type.to_s
        when 'legacy', 'ecs-v1'
          ::File.join(BASE_PATH, type)
        else
          raise ArgumentError, "#{type.inspect} path not supported"
        end
      end

    end
  end
end
