const rules = {
    // globall rules
    // Rule to check if the value is required
    required: (value, error) => !!value || error,
    // Rule to check minimum length
    min: (limit) => (val, error) =>
        val.length >= limit || error.replace('{value}', val).replace('{limit}', limit),

    // Rule to check maximum length
    max: (limit) => (val, error) =>
        val.length <= limit || error.replace('{value}', val).replace('{limit}', limit),

    // Starting String rules
    // Rule to check if the value starts with a specified substring
    startWith: (value, substring, error) => {
        return value.startsWith(substring) || error.replace('{value}', value).replace('{substring}', substring);
    },

    // Rule to check if the value ends with a specified substring
    endWith: (value, substring, error) => {
        return value.endsWith(substring) || error.replace('{value}', value).replace('{substring}', substring);
    },

    // Rule to check if the value includes a specified substring
    include: (value, substring, error) => {
        return value.includes(substring) || error.replace('{value}', value).replace('{substring}', substring);
    },

    // Rule to validate password strength
    password: (value, error) => {
        const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{8,})/; // Regex for strong password
        return pattern.test(value) || error; // Check if password matches pattern
    },

    // Rule to check password confirmation
    password_confirmation: (password) => (val, error) =>
        val === password || error, // Ensure passwords match

    // Rule to validate email format
    email: (value, error) => {
        const pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Regex for email
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Starting Number rules
    // Rule to validate integer format
    int: (value, error) => {
        const pattern = /^-?\d+$/; // Regex for integer
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate numeric format (including decimals)
    number: (value, error) => {
        const pattern = /^-?\d*\.?\d+$/; // Regex for number
        return pattern.test(value) || error.replace('{value}', value);
    },

    between: (value, min, max, error) => {
        // Check if value is within the specified range
        return (value >= min && value <= max) || error.replace('{value}', value).replace('{min}', min).replace('{max}', max);
    },
    
    // Rule to validate monetary format
    money: (value, error) => {
        const pattern = /^\d+(\.\d{1,2})?$/; // Regex for money format
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate date format (YYYY-MM-DD)
    dateformat: (value, format, error) => {
        const pattern = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])$/; // Regex for date
        const isValid = pattern.test(value);
        return isValid || error.replace('{value}', value).replace('{format}', format);
    },

    // Rule to validate that a date is in the past
    pastDate: (value, error) => {
        const date = new Date(value);
        return date < new Date() || error.replace('{value}', value);
    },

    // Rule to validate that a date is in the future
    futureDate: (value, error) => {
        const date = new Date(value);
        return date > new Date() || error.replace('{value}', value);
    },

    // Rule to validate phone number format (E.164)
    phone: (value, error) => {
        const pattern = /^\+?[1-9]\d{1,14}$/; // E.164 format for phone numbers
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate URL format
    url: (value, error) => {
        const pattern = /^(https?:\/\/)?([\w.-]+)+(:\d+)?(\/[\w.-]*)*$/; // Regex for URL
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate using a custom regex
    regex: (value, regex, error) => {
        return regex.test(value) || error.replace('{value}', value); // Validate against custom regex
    },

    // Rule to validate that input contains only alphabetic characters
    alpha: (value, error) => {
        const pattern = /^[A-Za-z]+$/; // Regex for alphabetic characters
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate that input is alphanumeric
    alphanumeric: (value, error) => {
        const pattern = /^[A-Za-z0-9]+$/; // Regex for alphanumeric characters
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to ensure input does not contain only whitespace
    noWhitespace: (value, error) => {
        return value.trim() !== "" || error.replace('{value}', value); // Check for whitespace
    },

    // Rule to validate credit card numbers using regex
    creditCard: (value, error) => {
        const pattern = /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|7[0-9]{15})$/; // Regex for credit cards
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to check if the value is in an allowed list
    allowedValues: (value, allowedList, error) => {
        return allowedList.includes(value) || error.replace('{value}', value); // Validate against allowed values
    },

    // Rule to ensure the value is not equal to a forbidden value
    notEqual: (value, forbiddenValue, error) => {
        return value !== forbiddenValue || error.replace('{value}', value).replace('{forbiddenValue}', forbiddenValue); // Check inequality
    },

    // Rule to validate that the input is a single character
    singleCharacter: (value, error) => {
        return value.length === 1 || error.replace('{value}', value); // Check for single character
    },

    // Rule to validate that input contains no special characters
    noSpecialChars: (value, error) => {
        const pattern = /^[A-Za-z0-9 ]*$/; // Allows letters, numbers, and spaces
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to match input against a specified pattern
    matchPattern: (value, pattern, error) => {
        return pattern.test(value) || error.replace('{value}', value); // Validate against provided pattern
    },

    // Rule to validate that input is a valid JSON string
    json: (value, error) => {
        try {
            JSON.parse(value); // Attempt to parse JSON
            return true; // Valid JSON
        } catch {
            return error.replace('{value}', value); // Invalid JSON
        }
    },

    // Rule to validate hex color codes
    hexColor: (value, error) => {
        const pattern = /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$/; // Regex for hex color codes
        return pattern.test(value) || error.replace('{value}', value);
    },

    // Rule to validate file size
    file: (value, size, error) =>
        !value.length || (value[0].size < size) || error.replace('{size}', size), // Check file size

    // Rule to validate file type
    fileType: (value, types, error) => {
        // Check if the file array is empty
        if (!value.length) return true; // No file selected, so consider it valid

        // Validate against the provided types
        return types.includes(value[0].type) || error.replace('{value}', value[0].name); // Check file type
    },
};

export default rules;
