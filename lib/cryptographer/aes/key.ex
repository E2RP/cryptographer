defmodule Cryptographer.Aes.Key do
  alias Cryptographer.Aes.Table

  def generate(), do: 8 |> :crypto.strong_rand_bytes() |> Base.encode16()

  def one_byte_left_rotate_word(word) do
    word
    |> Enum.with_index(0)
    |> Enum.reduce([], fn {char, i}, acc -> List.insert_at(acc, i - 1, char) end)
    |> Enum.join()
  end

  defp sub_byte(byte), do: Table.get_at(byte)

  def sub_word(word), do: word |> sub_word([]) |> Enum.reverse()
  defp sub_word(<<>>, acc), do: acc
  defp sub_word(<<byte::8, rest::binary>>, acc), do: sub_word(rest, [sub_byte(byte) | acc])

  def round_constant(j), do: round_constant(j, 0x01)
  defp round_constant(1, acc), do: acc * 0x01
  defp round_constant(j, acc), do: round_constant(j - 1, 0x02 * acc)
end
