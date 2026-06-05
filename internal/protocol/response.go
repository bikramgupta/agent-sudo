package protocol

// SuggestedReasonShape is the template returned to agents when a reason is
// rejected, so the agent can revise and retry through the same CLI.
const SuggestedReasonShape = "Need to <action> because <project/task requires it>; target is <scope>."

// Denial builds a generic structured decline carrying the request id, decision
// code, human-readable message, and whether the agent may revise and retry.
func Denial(requestID, decision, message string, retryable bool) *BrokerResponse {
	return &BrokerResponse{
		RequestID: requestID,
		Decision:  decision,
		Message:   message,
		Retryable: retryable,
	}
}

// ReasonInvalid builds a retryable REASON_INVALID response that tells the agent
// which audit context fields are missing and the reason shape to aim for.
func ReasonInvalid(requestID, message string, missing []string) *BrokerResponse {
	return &BrokerResponse{
		RequestID:            requestID,
		Decision:             DecisionReasonInvalid,
		Message:              message,
		Retryable:            true,
		Missing:              missing,
		SuggestedReasonShape: SuggestedReasonShape,
	}
}
