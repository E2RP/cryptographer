defmodule Cryptographer.Aes.Key do
  alias Cryptographer.Aes.Table

  def generate(), do: 8 |> :crypto.strong_rand_bytes() |> Base.encode16()

  def one_bit_rotation(word) do
    word
    |> Enum.with_index(0)
    |> Enum.reduce([], fn {char, i}, acc -> List.insert_at(acc, i - 1, char) end)
    |> Enum.join()
  end

  defp sub_byte(byte), do: Table.get_at(byte)

  def sub_word(word), do: sub_word(word, [])
  defp sub_word(<<>>, acc), do: acc
  defp sub_word(<<byte::8, rest::binary>>, acc), do: sub_word(rest, acc ++ [sub_byte(byte)])

  def round_constant(j), do: rc(j, 0x01)
  defp rc(1, acc), do: acc * 0x01
  defp rc(j, acc), do: rc(j - 1, 0x02 * acc)
end
