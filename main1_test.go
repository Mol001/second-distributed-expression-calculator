package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseExpr(t *testing.T) {
	tests := []struct {
		name     string
		input1   string
		input2   int
		expected map[int][][]string
		err      string
	}{
		{
			name:   "Single operand",
			input1: "2+2+2+876",
			input2: 1,
			expected: map[int][][]string{
				1: {{"2", "+", "2", "op1"}, {"op1", "+", "2", "op2"}, {"op2", "+", "876", "op3"}},
			},
			err: "200. Выражение успешно принято, распаршено и принято к обработке",
		},
		{
			name:   "2",
			input1: "2-2",
			input2: 1,
			expected: map[int][][]string{
				1: {{"2", "-", "2", "op1"}},
			},
			err: "200. Выражение успешно принято, распаршено и принято к обработке",
		},
		{
			name:   "3",
			input1: "2-1*41",
			input2: 1,
			expected: map[int][][]string{
				1: {{"1", "*", "41", "op1"}, {"2", "-", "op1", "op2"}},
			},
			err: "200. Выражение успешно принято, распаршено и принято к обработке",
		},
		{
			name:   "4",
			input1: "2+2+2+2/2",
			input2: 1,
			expected: map[int][][]string{
				1: {{"2", "/", "2", "op1"}, {"2", "+", "2", "op2"}, {"op2", "+", "2", "op3"}, {"op3", "+", "op1", "op4"}},
			},
			err: "200. Выражение успешно принято, распаршено и принято к обработке",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseExpr(tt.input1, tt.input2)
			if err != tt.err {
				t.Errorf("parseExpr(%v, %v) error = %v; want %v", tt.input1, tt.input2, err, tt.err)
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseExpr(%v, %v) = %v; want %v", tt.input1, tt.input2, result, tt.expected)
			}
		})
	}
}

func TestMaxOperand(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected string
	}{
		{
			name:     "Single operand",
			input:    []string{"op1"},
			expected: "op1",
		},
		{
			name:     "Multiple operands",
			input:    []string{"op1", "op2", "op3"},
			expected: "op3",
		},
		{
			name:     "No operands",
			input:    []string{},
			expected: "",
		},
		{
			name:     "Mixed operands and non-operands",
			input:    []string{"op1", "non-op", "op2", "op3"},
			expected: "op3",
		},
		{
			name:     "Duplicate highest operand",
			input:    []string{"op1", "op2", "op2"},
			expected: "op2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maxOperand(tt.input)
			if result != tt.expected {
				t.Errorf("maxOperand(%v) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEvaluateArithmeticExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected int
	}{
		{
			name:     "Addition",
			expr:     "5+3",
			expected: 8,
		},
		{
			name:     "Subtraction",
			expr:     "10-5",
			expected: 5,
		},
		{
			name:     "Multiplication",
			expr:     "2*3",
			expected: 6,
		},
		{
			name:     "Division",
			expr:     "10/2",
			expected: 5,
		},
		{
			name:     "Division by zero",
			expr:     "10/0",
			expected: 0,
		},
		{
			name:     "Invalid expression",
			expr:     "10/",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluateArithmeticExpression(tt.expr)
			if result != tt.expected {
				t.Errorf("evaluateArithmeticExpression(%v) = %v; want %v", tt.expr, result, tt.expected)
			}
		})
	}
}

func TestSliceContains(t *testing.T) {
	tests := []struct {
		name     string
		slice    []int
		element  int
		expected bool
	}{
		{
			name:     "Element exists",
			slice:    []int{1, 2, 3, 4, 5},
			element:  3,
			expected: true,
		},
		{
			name:     "Element does not exist",
			slice:    []int{1, 2, 3, 4, 5},
			element:  6,
			expected: false,
		},
		{
			name:     "Empty slice",
			slice:    []int{},
			element:  1,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sliseContains(tt.slice, tt.element)
			if result != tt.expected {
				t.Errorf("sliseContains(%v, %v) = %v; want %v", tt.slice, tt.element, result, tt.expected)
			}
		})
	}
}

func TestSplitExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected []string
	}{
		{
			name:     "Simple addition",
			expr:     "5+3",
			expected: []string{"5", "+", "3"},
		},
		{
			name:     "Multiplication and division",
			expr:     "2*3/4",
			expected: []string{"2", "*", "3", "/", "4"},
		},
		{
			name:     "Subtraction and addition",
			expr:     "10-5+2",
			expected: []string{"10", "-", "5", "+", "2"},
		},
		{
			name:     "Spaces and multiple operators",
			expr:     " 10 - 5 + 2 ",
			expected: []string{"10", "-", "5", "+", "2"},
		},
		{
			name:     "Empty expression",
			expr:     "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitExpression(tt.expr)
			if !equal(result, tt.expected) {
				t.Errorf("splitExpression(%v) = %v; want %v", tt.expr, result, tt.expected)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func TestCheckArithmeticExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected bool
	}{
		{
			name:     "Valid expression",
			expr:     "1+2*3-4/5",
			expected: true,
		},
		{
			name:     "Invalid character",
			expr:     "1+2*3-4/5a",
			expected: false,
		},
		{
			name:     "Improper operator placement",
			expr:     "1+2*3-4/5*",
			expected: true,
		},
		{
			name:     "Empty expression",
			expr:     "",
			expected: true,
		},
		{
			name:     "Only numbers",
			expr:     "12345",
			expected: true,
		},
		{
			name:     "Only operators",
			expr:     "+-*/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkArithmeticExpression(tt.expr)
			if result != tt.expected {
				t.Errorf("checkArithmeticExpression(%v) = %v; want %v", tt.expr, result, tt.expected)
			}
		})
	}
}

func TestServeStaticFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString("Hello, World!"); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	t.Run("Serve valid file", func(t *testing.T) {
		handler := serveStaticFile(tmpFile.Name())
		req := httptest.NewRequest("GET", "/", nil)
		resp := httptest.NewRecorder()
		handler(resp, req)

		if resp.Code != http.StatusOK {
			t.Errorf("Expected status OK; got %v", resp.Code)
		}
		if resp.Body.String() != "Hello, World!" {
			t.Errorf("Expected body 'Hello, World!'; got %v", resp.Body.String())
		}
	})

	t.Run("Serve non-existent file", func(t *testing.T) {
		handler := serveStaticFile("non-existent-file")
		req := httptest.NewRequest("GET", "/", nil)
		resp := httptest.NewRecorder()
		handler(resp, req)

		if resp.Code != http.StatusNotFound {
			t.Errorf("Expected status NotFound; got %v", resp.Code)
		}
	})
}

func TestGetFormValue(t *testing.T) {
	t.Run("Valid integer", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/test", strings.NewReader("key=123"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		value := getFormValue(req, "key")
		if value != 123 {
			t.Errorf("Expected 123; got %v", value)
		}
	})
}
