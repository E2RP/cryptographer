defmodule Cryptographer.Aes do
  @type word_binary :: <<_::32>>
  @type word_byte_list :: [byte(), ...]
  @type word :: word_binary() | word_byte_list()

  @type words_binary :: <<_::_*32>>
  @type words_byte_list :: [word_byte_list(), ...]
  @type words :: words_binary() | words_byte_list()
end
