import pytest
from syslog_server.lib import client_handler, data_handler

# --------------------------------
# data_handler tests
# --------------------------------
def test_row_sanitize():
    example = ["Bannana", "Stuff", 0]
    goal = ["Bannana", "Stuff", 0, 0]
    result_1 = data_handler.row_sanitize("NaN", example)
    result_2 = data_handler.row_sanitize("NULL", example)
    result_3 = data_handler.row_sanitize(None, example)
    assert result_1 == goal
    assert result_2 == goal
    assert result_3 == goal

def test_element_find():
    example = "<BlahBlahBlah>1"
    assert data_handler.element_find("<", ">1", example) == ('BlahBlahBlah', '')
    assert data_handler.element_find("<", ">", example) == ("BlahBlahBlah", '1')

def test_element_split():
    example = "<BlahBlahBlah>1"
    assert data_handler.element_split(5, example) == ("<Blah", "BlahBlah>1")

def test_iterate_nulls():
    example = ["Beep", "Boop", "", ""]
    assert data_handler.iterate_nulls(example, 2, 0) == ["Beep", "Boop", "NULL", "NULL"]