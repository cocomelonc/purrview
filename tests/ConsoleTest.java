import lab.purrview.LabConsole;
public class ConsoleTest {
 public static void main(String[] args) {
  LabConsole c=new LabConsole();
  check(c.execute("help").startsWith("Locked"));
  c.unlock();check(c.execute("help").contains("whoami"));
  check(c.execute("cat note.txt").contains("fictional"));
  for(String cmd:new String[]{"sh", "ls; id", "cat /etc/passwd", "$(id)", "whoami\nls", "curl example.com"})check(c.execute(cmd).startsWith("Unknown"));
  check(c.execute(null).startsWith("Rejected"));
  check(c.execute(new String(new char[81])).startsWith("Rejected"));
  check(c.execute("clear").isEmpty());
  c.reset();check(c.execute("whoami").startsWith("Locked"));
  System.out.println("Console tests passed: gating, fixtures, reset, input bounds, shell syntax rejected.");
 }
 static void check(boolean value){if(!value)throw new AssertionError();}
}
