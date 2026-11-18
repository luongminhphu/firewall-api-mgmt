// ESLint cho frontend/js (ES module, không build): bắt tên không xác định / biến thừa khi tách module.
export default [{
  files: ["**/*.js"],
  languageOptions: {
    ecmaVersion: 2023, sourceType: "module",
    globals: { window: "readonly", document: "readonly", location: "readonly", history: "readonly", fetch: "readonly",
      localStorage: "readonly", setTimeout: "readonly", clearTimeout: "readonly", confirm: "readonly",
      FileReader: "readonly", URLSearchParams: "readonly", console: "readonly", Date: "readonly" },
  },
  rules: { "no-undef": "error", "no-unused-vars": ["error", { args: "none" }], "no-redeclare": "error",
  },
}];
