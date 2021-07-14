defmodule Cryptographer.AesTest do
  use ExUnit.Case

  alias Cryptographer.Aes
  alias Cryptographer.Aes.Key.Scheduler

  describe "encrypt/2" do
    test "anything idk" do
      key = <<0x54686174::32, 0x73206D79::32, 0x204B756E::32, 0x67204675::32>>
      message = <<0x00000101::32, 0x03030707::32, 0x0F0F1F1F::32, 0x3F3F7F7F::32>>

      assert Aes.encrypt(message, key) == result
    end
  end
end
