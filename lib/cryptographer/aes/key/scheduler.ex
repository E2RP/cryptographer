defmodule Cryptographer.Aes.Key.Scheduler do
  alias Cryptographer.Aes
  alias Cryptographer.Aes.{BinaryUtils, Key, SBox}

  @spec expand_key(key :: Key.t(), round :: pos_integer()) :: [Aes.word_binary(), ...]
  def expand_key(key, round) when is_binary(key) and round >= 1 do
    round_words = BinaryUtils.binary_to_word_list(key)

    round_words
    |> Enum.with_index()
    |> Enum.reduce(round_words, fn {word, i}, acc ->
      next_word =
        case i do
          0 -> BinaryUtils.bxor_words(word, g_function(Enum.at(acc, i + 3), round))
          i -> BinaryUtils.bxor_words(Enum.at(acc, i + 3), Enum.at(acc, i))
        end

      acc ++ [next_word]
    end)
    |> Enum.take(-4)
    |> Enum.into(<<>>, fn <<a::8, b::8, c::8, d::8>> -> <<a::8, b::8, c::8, d::8>> end)
  end

  @spec compute_round_constant(j :: pos_integer()) :: Aes.word_binary()
  @spec compute_round_constant(j :: pos_integer(), acc :: non_neg_integer()) :: pos_integer()
  def compute_round_constant(j),
    do: <<compute_round_constant(j, 0x01)::8, 0x00::8, 0x00::8, 0x00::8>>

  defp compute_round_constant(1, acc), do: acc

  defp compute_round_constant(j, acc) when acc >= 0x80 do
    compute_round_constant(j - 1, Bitwise.bxor(0x11B, 0x02 * acc))
  end

  defp compute_round_constant(j, acc), do: compute_round_constant(j - 1, 0x02 * acc)

  @spec g_function(word :: Aes.word_binary(), round :: pos_integer()) :: Aes.word_binary()
  defp g_function(word, round) do
    round_constant = compute_round_constant(round)

    word
    |> BinaryUtils.one_byte_left_rotate()
    |> SBox.sub_word()
    |> BinaryUtils.bxor_words(round_constant)
  end
end
