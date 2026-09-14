package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultTimeout is the per-request deadline. Local models on consumer hardware
// can take 3-5 minutes for a large prompt; 5 minutes is the default.
const DefaultTimeout = 5 * time.Minute

type Client struct {
	BaseURL string
	APIKey  string
	Model   string
	Timeout time.Duration // 0 → DefaultTimeout
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}

type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
}

func (c *Client) Chat(system, user string) (string, error) {
	messages := []message{}
	if system != "" {
		messages = append(messages, message{Role: "system", Content: system})
	}
	messages = append(messages, message{Role: "user", Content: user})

	body, err := json.Marshal(chatRequest{
		Model:    c.Model,
		Messages: messages,
		Stream:   false,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	timeout := c.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return "", fmt.Errorf("LLM unreachable (%s, model: %s): %w", c.BaseURL, c.Model, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", fmt.Errorf("LLM returned %d (body unreadable: %w)", resp.StatusCode, err)
		}
		return "", fmt.Errorf("LLM returned %d: %s", resp.StatusCode, string(raw))
	}

	var result chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("response decode failed: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no choices returned from LLM")
	}

	return result.Choices[0].Message.Content, nil
}