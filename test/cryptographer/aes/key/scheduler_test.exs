defmodule Cryptographer.Aes.Key.SchedulerTest do
  use ExUnit.Case

  alias Cryptographer.Aes.Key.Scheduler

  describe "one_byte_left_rotate_word/1" do
    test "returns a rotated word by one byte" do
      assert Scheduler.one_byte_left_rotate_word("ABCD") == "BCDA"
      assert Scheduler.one_byte_left_rotate_word("DABC") == "ABCD"
      assert Scheduler.one_byte_left_rotate_word("WXYZ") == "XYZW"
      assert Scheduler.one_byte_left_rotate_word("ZYXW") == "YXWZ"
    end
  end

  describe "sub_word/1" do
    test "returns a word with every byte correclty replaced according to the AES table" do
      assert Scheduler.sub_word("ABCD") == [0x83, 0x2C, 0x1A, 0x1B] |> list_to_binary()
      assert Scheduler.sub_word("KKKK") == [0xB3, 0xB3, 0xB3, 0xB3] |> list_to_binary()
      assert Scheduler.sub_word("WXYZ") == [0x5B, 0x6A, 0xCB, 0xBE] |> list_to_binary()
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

  defp list_to_binary([a, b, c, d]), do: <<a::8, b::8, c::8, d::8>>
end
