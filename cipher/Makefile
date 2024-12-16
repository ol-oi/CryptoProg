# Определяем переменные
CXX = g++
CXXFLAGS = -std=c++11 -Wall -O0 -g
LDFLAGS = -lcryptopp
SRC = main.cpp
OBJ = $(SRC:.cpp=.o)
TARGET = cipher

# Правило по умолчанию
all: $(TARGET)

# Правило для создания исполняемого файла
$(TARGET): $(OBJ)
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)

# Правило для компиляции исходных файлов в объектные
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Очистка сгенерированных файлов
clean:
	rm -f $(OBJ) $(TARGET)


