// STATIC FIXTURE ONLY. Never compile or execute.
class StaticFixture {
  String api_key = System.getenv("API_KEY");
  boolean auth_bypass = false;
  String indicator = "connect to the authenticated service";
}
