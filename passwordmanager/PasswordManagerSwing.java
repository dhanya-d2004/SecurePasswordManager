package passwordmanager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

public class PasswordManagerSwing extends JFrame {

    private char[] masterPassword;
    private byte[] salt;

    private List<Credential> credentials = new ArrayList<>();

    private JTextField websiteField;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTable credentialTable;
    private DefaultTableModel tableModel;
    private JTextField searchField;
    private JCheckBox showPassword;

    public PasswordManagerSwing() {
        setTitle("Password Manager");
        setSize(750, 550);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        loadOrGenerateSalt();
        initMasterPasswordDialog();
    }

    private void loadOrGenerateSalt() {
        try {
            salt = EncryptionUtil.loadSalt();
        } catch (Exception e) {
            salt = EncryptionUtil.generateSalt();
            EncryptionUtil.saveSalt(salt);
        }
    }

    private void initMasterPasswordDialog() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        JLabel label = new JLabel("Enter Master Password:");
        JPasswordField pwd = new JPasswordField();
        panel.add(label, BorderLayout.NORTH);
        panel.add(pwd, BorderLayout.CENTER);

        int option = JOptionPane.showConfirmDialog(this, panel, "Authentication",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (option == JOptionPane.OK_OPTION) {
            masterPassword = pwd.getPassword();
            credentials = FileHandler.load();

            if (!credentials.isEmpty()) {
                try {
                    EncryptionUtil.decrypt(credentials.get(0).getEncryptedPassword(), masterPassword, salt);
                } catch (Exception e) {
                    JOptionPane.showMessageDialog(this, "Wrong master password! Exiting.", "Error",
                            JOptionPane.ERROR_MESSAGE);
                    System.exit(0);
                }
            }
            initUI();
        } else {
            System.exit(0);
        }
    }

    private void initUI() {
        setLayout(new BorderLayout());

        // Input Panel
        JPanel inputPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Add New Credential"));

        inputPanel.add(new JLabel("Website:"));
        websiteField = new JTextField();
        inputPanel.add(websiteField);

        inputPanel.add(new JLabel("Username:"));
        usernameField = new JTextField();
        inputPanel.add(usernameField);

        inputPanel.add(new JLabel("Password:"));

        // Password field and Show checkbox
        JPanel passwordPanel = new JPanel(new BorderLayout());
        passwordField = new JPasswordField();
        showPassword = new JCheckBox("Show");
        showPassword.addActionListener(e -> {
            if (showPassword.isSelected()) {
                passwordField.setEchoChar((char) 0);
            } else {
                passwordField.setEchoChar('•');
            }
        });

        passwordPanel.add(passwordField, BorderLayout.CENTER);
        passwordPanel.add(showPassword, BorderLayout.EAST);
        inputPanel.add(passwordPanel);

        // Generate Password Button
        inputPanel.add(new JLabel(""));
        JButton generateButton = new JButton("Generate Password");
        generateButton.addActionListener(e -> {
            String generated = PasswordGenerator.generate(16);
            passwordField.setText(generated);
            showPassword.setSelected(true);
            passwordField.setEchoChar((char) 0); // Show password by default
        });
        inputPanel.add(generateButton);

        // Add & Save Buttons
        JButton addButton = new JButton("Add Credential");
        JButton saveButton = new JButton("Save & Exit");
        inputPanel.add(addButton);
        inputPanel.add(saveButton);

        add(inputPanel, BorderLayout.NORTH);

        // Table Panel
        tableModel = new DefaultTableModel(new String[] { "Website", "Username", "Password" }, 0) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        credentialTable = new JTable(tableModel);
        refreshTable();
        add(new JScrollPane(credentialTable), BorderLayout.CENTER);

        // Bottom Panel for Search and Delete
        JPanel bottomPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bottomPanel.setBorder(BorderFactory.createTitledBorder("Search / Delete"));

        bottomPanel.add(new JLabel("Website:"));
        searchField = new JTextField(15);
        bottomPanel.add(searchField);

        JButton searchButton = new JButton("Search");
        JButton deleteButton = new JButton("Delete Selected");

        bottomPanel.add(searchButton);
        bottomPanel.add(deleteButton);

        add(bottomPanel, BorderLayout.SOUTH);

        // Action listeners
        addButton.addActionListener(e -> addCredential());
        saveButton.addActionListener(e -> saveAndExit());
        searchButton.addActionListener(e -> searchCredential());
        deleteButton.addActionListener(e -> deleteSelectedCredential());

        setVisible(true);
    }

    private void addCredential() {
        String website = websiteField.getText().trim();
        String username = usernameField.getText().trim();
        char[] passwordChars = passwordField.getPassword();
        String password = new String(passwordChars);

        if (website.isEmpty() || username.isEmpty() || password.isEmpty()) {
            JOptionPane.showMessageDialog(this, "All fields must be filled.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        try {
            String encryptedPassword = EncryptionUtil.encrypt(password, masterPassword, salt);
            credentials.add(new Credential(website, username, encryptedPassword));
            refreshTable();

            websiteField.setText("");
            usernameField.setText("");
            passwordField.setText("");

            JOptionPane.showMessageDialog(this, "Credential added.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Encryption error: " + ex.getMessage(), "Error",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private void refreshTable() {
        tableModel.setRowCount(0);
        for (Credential c : credentials) {
            try {
                String decryptedPwd = EncryptionUtil.decrypt(c.getEncryptedPassword(), masterPassword, salt);
                tableModel.addRow(new Object[] { c.getWebsite(), c.getUsername(), decryptedPwd });
            } catch (Exception e) {
                tableModel.addRow(new Object[] { c.getWebsite(), c.getUsername(), "Error decrypting" });
            }
        }
    }

    private void searchCredential() {
        String search = searchField.getText().trim().toLowerCase();
        if (search.isEmpty()) {
            refreshTable();
            return;
        }

        tableModel.setRowCount(0);
        boolean found = false;
        for (Credential c : credentials) {
            if (c.getWebsite().toLowerCase().contains(search)) {
                try {
                    String decryptedPwd = EncryptionUtil.decrypt(c.getEncryptedPassword(), masterPassword, salt);
                    tableModel.addRow(new Object[] { c.getWebsite(), c.getUsername(), decryptedPwd });
                    found = true;
                } catch (Exception e) {
                    tableModel.addRow(new Object[] { c.getWebsite(), c.getUsername(), "Error decrypting" });
                }
            }
        }

        if (!found) {
            JOptionPane.showMessageDialog(this, "No credentials found for: " + search);
        }
    }

    private void deleteSelectedCredential() {
        int selectedRow = credentialTable.getSelectedRow();
        if (selectedRow == -1) {
            JOptionPane.showMessageDialog(this, "Select a row to delete.", "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String website = (String) tableModel.getValueAt(selectedRow, 0);
        credentials.removeIf(c -> c.getWebsite().equalsIgnoreCase(website));
        refreshTable();
        JOptionPane.showMessageDialog(this, "Credential deleted.");
    }

    private void saveAndExit() {
        FileHandler.save(credentials);
        JOptionPane.showMessageDialog(this, "Credentials saved. Exiting.");
        System.exit(0);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(PasswordManagerSwing::new);
    }
}
