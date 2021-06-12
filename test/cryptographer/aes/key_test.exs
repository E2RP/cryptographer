defmodule Cryptographer.Aes.KeyTest do
  use ExUnit.Case

  alias Cryptographer.Aes.Key

  describe "generate/0" do
    test "returns a randomly generated key of 128 bits" do
      assert <<_::128>> = Key.generate()

      assert <<_::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8, _::8,
               _::8, _::8>> = Key.generate()
    end
  end
end
