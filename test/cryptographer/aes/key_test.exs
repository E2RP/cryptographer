defmodule Cryptographer.Aes.KeyTest do
  use ExUnit.Case

  alias Cryptographer.Aes.Key

  describe "generate/0" do
    test "returns a randomly generated key of 128 bits (16 characters)" do
      assert String.length(Key.generate()) == 16
      assert String.length(Key.generate()) == 16
      assert String.length(Key.generate()) == 16
    end
  end
end
