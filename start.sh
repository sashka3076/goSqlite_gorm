
tmux new -s s -d
tmux send -t "s" "cd $HOME/MyWork/webssh2/app;./run.sh" Enter
tmux new -s ss -d
tmux send -t "ss" "cd $HOME/MyWork/goSqlite_gorm;./main" Enter


