defmodule Cryptographer.Aes.Key do
  @type t :: <<_::128>>

  @spec generate() :: t()
  def generate(), do: 16 |> :crypto.strong_rand_bytes()
end
