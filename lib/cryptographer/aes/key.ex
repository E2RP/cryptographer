defmodule Cryptographer.Aes.Key do
  alias Cryptographer.Aes.Table

  def generate(), do: 12 |> :crypto.strong_rand_bytes() |> Base.encode64()

  def expand(key, round) do
    round_words = key |> String.graphemes() |> Enum.chunk_every(4) |> Enum.map(&Enum.join/1)

    round_words
    |> Enum.with_index()
    |> Enum.reduce(round_words, fn {word, i}, acc ->
      next_word =
        case i do
          0 -> bxor_words(word, g(Enum.at(acc, i + 3), round))
          i -> bxor_words(Enum.at(acc, i + 3), Enum.at(acc, i))
        end

      acc ++ [next_word]
    end)
    |> Enum.take(-4)
  end

  defp bxor_words(word_a, word_b) do
    word_a |> bxor_words(word_b, []) |> list_to_binary()
  end

  defp bxor_words(<<>>, <<>>, acc), do: acc

  defp bxor_words(<<a::8, a_rest::binary>>, <<b::8, b_rest::binary>>, acc) do
    bxor_words(a_rest, b_rest, acc ++ [Bitwise.bxor(a, b)])
  end

  defp g(word, round) do
    round_constant = <<compute_round_constant(round)::32>>
    word |> one_byte_left_rotate_word() |> sub_word() |> bxor_words(round_constant)
  end

  def one_byte_left_rotate_word(word) do
    word
    |> String.graphemes()
    |> Enum.with_index(0)
    |> Enum.reduce([], fn {char, i}, acc -> List.insert_at(acc, i - 1, char) end)
    |> Enum.join()
  end

  def sub_word(word), do: word |> sub_word([]) |> Enum.reverse() |> list_to_binary()
  defp sub_word(<<>>, acc), do: acc
  defp sub_word(<<byte::8, rest::binary>>, acc), do: sub_word(rest, [sub_byte(byte) | acc])

  def compute_round_constant(j), do: compute_round_constant(j, 0x01)
  defp compute_round_constant(1, acc), do: acc
  defp compute_round_constant(j, acc) when acc >= 0x80 do
    compute_round_constant(j - 1, Bitwise.bxor(0x11B, 0x02 * acc))
  end

  defp compute_round_constant(j, acc), do: compute_round_constant(j - 1, 0x02 * acc)

  defp sub_byte(byte), do: Table.get_at(byte)

  defp list_to_binary([a, b, c, d]), do: <<a::8, b::8, c::8, d::8>>
end
