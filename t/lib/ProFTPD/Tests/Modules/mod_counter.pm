package ProFTPD::Tests::Modules::mod_counter;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use File::Copy;
use File::Path qw(mkpath rmtree);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  counter_retr_max_readers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_stor_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_stor_max_writers_exceeded_hidden_stores_issue6 => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_appe_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_dele_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_rnfr_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_rnto_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_toplevel => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_toplevel_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_midlevel => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_midlevel_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_bottomlevel => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_bottomlevel_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_none => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_none_chrooted => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_using_vhost => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_using_anon => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_using_anon_subdir => {
    order => ++$order,
    test_class => [qw(forking rootprivs)],
  },

  counter_closest_matching_file_using_globs => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_closest_matching_file_using_globs_and_exact => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  counter_vroot_retr_max_readers_exceeded => {
    order => ++$order,
    test_class => [qw(forking mod_vroot)],
  },

  counter_vroot_retr_max_readers_exceeded_in_subdir => {
    order => ++$order,
    test_class => [qw(forking mod_vroot)],
  },

  counter_vroot_stor_max_writers_exceeded => {
    order => ++$order,
    test_class => [qw(forking mod_vroot)],
  },

  counter_vroot_stor_max_writers_exceeded_in_subdir => {
    order => ++$order,
    test_class => [qw(forking mod_vroot)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub counter_retr_max_readers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");
  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterFile => $counter_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory />
  CounterMaxReaders 1
</Directory>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "$test_file: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub counter_stor_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->stor_raw($test_file);
      if ($conn2) {
        die("STOR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_stor_max_writers_exceeded_hidden_stores_issue6 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'counter:20',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',
    HiddenStores => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->stor_raw($test_file);
      if ($conn2) {
        die("STOR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 550;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: Temporary hidden file";
        $self->assert(qr/$expected/, $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_appe_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->appe_raw($test_file);
      if ($conn2) {
        die("APPE $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_dele_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to delete the same file
      eval { $client2->dele($test_file) };
      unless ($@) {
        die("DELE $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_rnfr_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to rename the same file
      eval { $client2->rnfr($test_file) };
      unless ($@) {
        die("RNFR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_rnto_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = 'test.txt';

  my $test_file2 = File::Spec->rel2abs("$tmpdir/test2.txt");
  if (open(my $fh, "> $test_file2")) {
    close($fh);

  } else {
    die("Can't open $test_file2: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR $test_file: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to rename another file
      # to file being uploaded
      $client2->rnfr($test_file2);

      eval { $client2->rnto($test_file) };
      unless ($@) {
        die("RNTO $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_toplevel {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_toplevel_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_midlevel {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  unless (copy($config_file, "$sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);
      $client1->cwd("foo");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);
      $client2->cwd("foo");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_midlevel_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  unless (copy($config_file, "$sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);
      $client1->cwd("foo");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);
      $client2->cwd("foo");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_bottomlevel {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  unless (copy($config_file, "$sub_sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);
      $client1->cwd("foo/bar");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);
      $client2->cwd("foo/bar");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_bottomlevel_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
CounterFile $toplevel_tab
<Directory $sub_dir>
  CounterFile $subdir_tab
</Directory>
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  unless (copy($config_file, "$sub_sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);
      $client1->cwd("foo/bar");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);
      $client2->cwd("foo/bar");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_none {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      unless ($conn2) {
        die("RETR $test_file failed unexpectedly: " . $client2->response_code()
          . " " . $client2->response_msg());
      }

      my $buf;
      $conn2->read($buf, 8192);
      $conn2->close();

      $resp_code = $client2->response_code();
      $resp_msg = $client2->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_none_chrooted {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory $sub_sub_dir>
  CounterFile $subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      unless ($conn2) {
        die("RETR $test_file failed unexpectedly: " . $client2->response_code()
          . " " . $client2->response_msg());
      }

      my $buf;
      $conn2->read($buf, 8192);
      $conn2->close();

      $resp_code = $client2->response_code();
      $resp_msg = $client2->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_using_vhost {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    Port => '0',

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  $port = ProFTPD::TestSuite::Utils::get_high_numbered_port();

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<VirtualHost 127.0.0.1>
  ServerName \"TJ's VirtualHost Server\"
  Port $port
  AuthUserFile $auth_user_file
  AuthGroupFile $auth_group_file

  CounterEngine on
  CounterLog $log_file
  CounterMaxReaders 1
  CounterFile $toplevel_tab
</VirtualHost>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_using_anon {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my ($config_user, $config_group) = config_get_identity();

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $config_user, $passwd, $uid, $gid, '/tmp',
    '/bin/bash');
  auth_group_write($auth_group_file, $config_group, $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    Anonymous => {
      $home_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',

        CounterFile => $toplevel_tab,
        CounterMaxReaders => 1,
      },
    },

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my $port;
  ($port, $config_user, $config_group) = config_write($config_file, $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login('anonymous', 'ftp@nospam.org');

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login('anonymous', 'ftp@nospam.org');

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_using_anon_subdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my ($config_user, $config_group) = config_get_identity();

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $config_user, $passwd, $uid, $gid, '/tmp',
    '/bin/bash');
  auth_group_write($auth_group_file, $config_group, $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    Anonymous => {
      $home_dir => {
        User => $config_user,
        Group => $config_group,
        UserAlias => "anonymous $config_user",
        RequireValidShell => 'off',

        Directory => {
          $sub_dir => {
            CounterMaxReaders => 1,
            CounterFile => $subdir_tab,
          },
        },
      },
    },

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my $port;
  ($port, $config_user, $config_group) = config_write($config_file, $config);

  unless (copy($config_file, "$sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login('anonymous', 'ftp@nospam.org');
      $client1->cwd('foo');

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login('anonymous', 'ftp@nospam.org');
      $client2->cwd('foo');

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          test_msg("Expected $expected, got $resp_code"));

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          test_msg("Expected '$expected', got '$resp_msg'"));
      }

      my $buf;
      $conn->read($buf, 8192);
      $conn->close();

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();

      $expected = 226;
      $self->assert($expected == $resp_code,
        test_msg("Expected $expected, got $resp_code"));

      $expected = "Transfer complete";
      $self->assert($expected eq $resp_msg,
        test_msg("Expected '$expected', got '$resp_msg'"));

      $client2->quit();
      $client1->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_closest_matching_file_using_globs {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $sub_dir = File::Spec->rel2abs("$tmpdir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$tmpdir/foo/bar");
  mkpath($sub_sub_dir);

  if ($< == 0) {
    unless (chmod(0755, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $sub_dir to 0755: $!");
    }

    unless (chown($setup->{uid}, $setup->{gid}, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $sub_dir to $setup->{uid}/$setup->{gid}: $!");
    }
  }

  my $toplevel_tab = File::Spec->rel2abs("$tmpdir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    my $config_sub_dir = $sub_dir;
    my $config_subsubdir_tab = $subsubdir_tab;

    if ($^O eq 'darwin') {
      $config_sub_dir = '/private' . $config_sub_dir;
      $config_subsubdir_tab = '/private' . $config_subsubdir_tab;
    }

    print $fh <<EOC;
<Directory $config_sub_dir/*/>
  CounterFile $config_subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  unless (copy($setup->{config_file}, "$sub_sub_dir/counter.conf")) {
    die("Can't copy $setup->{config_file} to '$sub_sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});
      $client1->cwd("foo/bar");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});
      $client2->cwd("foo/bar");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "$test_file: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub counter_closest_matching_file_using_globs_and_exact {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/counter.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/counter.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/counter.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/counter.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/counter.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  my $sub_dir = File::Spec->rel2abs("$home_dir/foo");
  mkpath($sub_dir);

  my $sub_sub_dir = File::Spec->rel2abs("$home_dir/foo/bar");
  mkpath($sub_sub_dir);

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir, $sub_dir, $sub_sub_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, 'ftpd', $gid, $user);

  my $toplevel_tab = File::Spec->rel2abs("$home_dir/counter.tab");
  my $subdir_tab = File::Spec->rel2abs("$sub_dir/counter.tab");
  my $subsubdir_tab = File::Spec->rel2abs("$sub_sub_dir/counter.tab");

  my $test_file = 'counter.conf';

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $log_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    my $config_sub_dir = $sub_dir;
    my $config_subdir_tab = $subdir_tab;

    my $config_subsub_dir = $sub_sub_dir;
    my $config_subsubdir_tab = $subsubdir_tab;

    if ($^O eq 'darwin') {
      $config_sub_dir = '/private' . $config_sub_dir;
      $config_subdir_tab = '/private' . $config_subdir_tab;
      $config_subsub_dir = '/private' . $config_subsub_dir;
      $config_subsubdir_tab = '/private' . $config_subsubdir_tab;
    }

    print $fh <<EOC;
<Directory $config_sub_dir/*>
  CounterFile $config_subdir_tab
</Directory>
<Directory $config_subsub_dir>
  CounterFile $config_subsubdir_tab
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  unless (copy($config_file, "$sub_sub_dir/counter.conf")) {
    die("Can't copy $config_file to '$sub_sub_dir/counter.conf': $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client1->login($user, $passwd);
      $client1->cwd("foo/bar");

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client2->login($user, $passwd);
      $client2->cwd("foo/bar");

      my $conn = $client1->retr_raw($test_file);
      unless ($conn) {
        die("Failed to RETR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      my ($resp_code, $resp_msg);
      my $expected;

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw($test_file);
      if ($conn2) {
        die("RETR $test_file succeeded unexpectedly");

      } else {
        $resp_code = $client2->response_code();
        $resp_msg = $client2->response_msg();

        $expected = 450;
        $self->assert($expected == $resp_code,
          "Expected response code $expected, got $resp_code");

        $expected = "$test_file: File busy";
        $self->assert($expected eq $resp_msg,
          "Expected response message '$expected', got '$resp_msg'");
      }

      my $buf;
      $conn->read($buf, 8192);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub counter_vroot_retr_max_readers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $test_file = File::Spec->rel2abs("$tmpdir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20 vroot:20 vroot.fsio:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AllowOverwrite => 'on',
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterFile => $counter_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_vroot.c' => {
        VRootEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn = $client1->retr_raw('test.dat');
      unless ($conn) {
        die("Failed to RETR test.d: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw('test.dat');
      if ($conn2) {
        die("RETR test.dat succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "test.dat: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf;
      $conn->read($buf, 8192, 15);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub counter_vroot_retr_max_readers_exceeded_in_subdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $test_file = File::Spec->rel2abs("$sub_dir/test.dat");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20 vroot:20 vroot.fsio:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AllowOverwrite => 'on',
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterFile => $counter_file,
        CounterMaxReaders => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_vroot.c' => {
        VRootEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn = $client1->retr_raw('test.d/test.dat');
      unless ($conn) {
        die("Failed to RETR test.d/test.d: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->retr_raw('test.d/test.dat');
      if ($conn2) {
        die("RETR test.d/test.dat succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "test.d/test.dat: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf;
      $conn->read($buf, 8192, 15);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub counter_vroot_stor_max_writers_exceeded {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");
  my $test_file = 'test.dat';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20 vroot:20 vroot.fsio:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AllowOverwrite => 'on',
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterFile => $counter_file,
        CounterMaxWriters => 1,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_vroot.c' => {
        VRootEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->stor_raw($test_file);
      if ($conn2) {
        die("STOR $test_file succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "$test_file: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf = 'Hello, World!\n';
      $conn->write($buf, length($buf));
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub counter_vroot_stor_max_writers_exceeded_in_subdir {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'counter');

  my $counter_file = File::Spec->rel2abs("$tmpdir/counter.tab");

  my $sub_dir = File::Spec->rel2abs("$tmpdir/test.d");
  mkpath($sub_dir);

  my $test_file = 'test.d/test.dat';

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'counter:20 vroot:20 vroot.fsio:20',

    AuthUserFile => $setup->{auth_user_file},
    AuthGroupFile => $setup->{auth_group_file},
    AllowOverwrite => 'on',
    DefaultRoot => '~',

    IfModules => {
      'mod_counter.c' => {
        CounterEngine => 'on',
        CounterLog => $setup->{log_file},
        CounterFile => $counter_file,
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_vroot.c' => {
        VRootEngine => 'on',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<Directory /test.d/>
  CounterMaxWriters 1
</Directory>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client1 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client1->login($setup->{user}, $setup->{passwd});

      my $client2 = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port, 0, 1);
      $client2->login($setup->{user}, $setup->{passwd});

      my $conn = $client1->stor_raw($test_file);
      unless ($conn) {
        die("Failed to STOR: " . $client1->response_code() . " " .
          $client1->response_msg());
      }

      # Now, before we close this data connection, try to open another
      # data connection for the same file.
      my $conn2 = $client2->stor_raw($test_file);
      if ($conn2) {
        die("STOR $test_file succeeded unexpectedly");
      }

      my $resp_code = $client2->response_code();
      my $resp_msg = $client2->response_msg();

      my $expected = 450;
      $self->assert($expected == $resp_code,
        "Expected response code $expected, got $resp_code");

      $expected = "$test_file: File busy";
      $self->assert($expected eq $resp_msg,
        "Expected response message '$expected', got '$resp_msg'");

      my $buf = "Hello, World!\n";
      $conn->write($buf, length($buf), 15);
      eval { $conn->close() };

      $resp_code = $client1->response_code();
      $resp_msg = $client1->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $client2->quit();
      $client1->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
