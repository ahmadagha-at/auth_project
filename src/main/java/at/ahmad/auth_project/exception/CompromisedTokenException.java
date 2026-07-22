package at.ahmad.auth_project.exception;

public class CompromisedTokenException extends RefreshTokenException {
    public CompromisedTokenException(String message) {
        super(message);
    }
}
