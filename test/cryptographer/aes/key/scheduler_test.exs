defmodule Cryptographer.Aes.Key.SchedulerTest do
  use ExUnit.Case
  alias Cryptographer.Aes.Key.Scheduler

  # describe "expand_key/2" do
  #   setup do
  #     %{key: <<126, 220, 51, 201, 57, 209, 144, 204, 152, 147, 172, 251, 212, 102, 205, 245>>}
  #   end

  #   test "returns a 128 bit key correctly expanded", %{key: key} do
  #     assert Scheduler.expand_key(key, 1) |> String.length() == 8*16
  #   end
  # end

  describe "one_byte_left_rotate_word/1" do
    test "returns a string rotated one byte to the left when argument is a string" do
      assert Scheduler.one_byte_left_rotate("ABCD") == "BCDA"
      assert Scheduler.one_byte_left_rotate("DABC") == "ABCD"
      assert Scheduler.one_byte_left_rotate("WXYZ") == "XYZW"
    end

    test "returns a binary rotated one byte to the left when argument is a binary" do
      assert Scheduler.one_byte_left_rotate(<<1::8, 2::8, 3::8, 4::8>>) ==
               <<2::8, 3::8, 4::8, 1::8>>

      assert Scheduler.one_byte_left_rotate(<<255::8, 0::8, 78::8, 96::8>>) ==
               <<0::8, 78::8, 96::8, 255::8>>

      assert Scheduler.one_byte_left_rotate(<<127::8, 65::8, 30::8, 47::8>>) ==
               <<65::8, 30::8, 47::8, 127::8>>
    end

    test "returns a list rotated one byte to the left when argument is a list" do
      assert Scheduler.one_byte_left_rotate([1, 2, 3, 4]) == [2, 3, 4, 1]
      assert Scheduler.one_byte_left_rotate([255, 0, 30, 47]) == [0, 30, 47, 255]
      assert Scheduler.one_byte_left_rotate([127, 65, 30, 47]) == [65, 30, 47, 127]
    end
  end

  describe "sub_word/1" do
    test "returns a word with every byte correclty replaced according to the AES table" do
      assert Scheduler.sub_word("ABCD") == <<0x83::8, 0x2C::8, 0x1A::8, 0x1B::8>>
      assert Scheduler.sub_word("KKKK") == <<0xB3::8, 0xB3::8, 0xB3::8, 0xB3::8>>
      assert Scheduler.sub_word("WXYZ") == <<0x5B::8, 0x6A::8, 0xCB::8, 0xBE::8>>
    end
  end

  describe "round_constant/1" do
    test "returns the round constant correctly calculated regardig the round number" do
      assert Scheduler.compute_round_constant(1) == 0x01
      assert Scheduler.compute_round_constant(2) == 0x02
      assert Scheduler.compute_round_constant(3) == 0x04
      assert Scheduler.compute_round_constant(4) == 0x08
      assert Scheduler.compute_round_constant(5) == 0x10
      assert Scheduler.compute_round_constant(6) == 0x20
      assert Scheduler.compute_round_constant(7) == 0x40
      assert Scheduler.compute_round_constant(8) == 0x80
      assert Scheduler.compute_round_constant(9) == 0x1B
      assert Scheduler.compute_round_constant(10) == 0x36
    end
  end
end
