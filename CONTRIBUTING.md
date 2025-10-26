# Contributing to Deep Recon Tool

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)
- Relevant logs or screenshots

### Suggesting Features

Feature requests are welcome! Please:
- Check if the feature already exists
- Clearly describe the feature
- Explain why it would be useful
- Consider the implementation impact

### Submitting Code

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/deep-recon-tool.git
   cd deep-recon-tool
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow the existing code style
   - Add comments for complex logic
   - Update documentation if needed

4. **Test Your Changes**
   ```bash
   python3 verify_install.py
   python3 deep_recon_v2.py -t scanme.nmap.org
   ```

5. **Commit**
   ```bash
   git add .
   git commit -m "Add feature: your feature description"
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Code Standards

### Python Style
- Follow PEP 8 guidelines
- Use type hints where appropriate
- Maximum line length: 100 characters
- Use descriptive variable names

### Documentation
- Update README.md for major changes
- Add docstrings to new functions
- Update relevant documentation files

### Testing
- Test on Kali Linux and Ubuntu
- Verify all tools still work
- Check for error handling

## 🔒 Security

- Never commit sensitive data
- Report security vulnerabilities privately
- Follow responsible disclosure practices

## 📜 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## ❓ Questions

If you have questions, feel free to:
- Open a discussion on GitHub
- Create an issue for clarification
- Check existing documentation

Thank you for contributing! 🎉
