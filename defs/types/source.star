"""Source code and scripts."""

type("source", parents = ["text"], abstract = True, description = "Source code and scripts")

type("source.bash", parents = ["source.shell"], mime = "application/bash", ext = ["bash"], description = "Bash script")
type("source.java", parents = ["source"], mime = "text/x-java-source", ext = ["java"], description = "Java source")
type("source.node", parents = ["source"], mime = "application/javascript", ext = ["js", "mjs", "cjs"], description = "JavaScript (Node) script")
type("source.perl", parents = ["source"], mime = "application/perl", ext = ["pl", "pm", "pod", "t"], description = "Perl source")
type("source.php", parents = ["source"], mime = "application/php", ext = ["phar", "php", "php-s", "php3", "php4", "php5", "php7", "phps", "pht", "phtml"], description = "PHP source")
type("source.python", parents = ["source"], mime = "application/python", ext = ["py", "pyc", "pyd", "pyo", "pyw", "pyz"], description = "Python source")
type("source.ruby", parents = ["source"], mime = "application/ruby", ext = ["rb"], description = "Ruby source")
type("source.shell", parents = ["source"], mime = "application/sh", ext = ["sh"], description = "POSIX shell script")
