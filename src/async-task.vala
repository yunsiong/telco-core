internal abstract class Telco.AsyncTask<T> : Object {
	private MainLoop loop;
	private bool completed;
	private Mutex mutex;
	private Cond cond;

	private T result;
	private GLib.Error? error;
	protected Cancellable? cancellable;

	public T execute (Cancellable? cancellable) throws Error, IOError {
		this.cancellable = cancellable;

		MainContext main_context = get_main_context ();

		if (main_context.is_owner ())
			loop = new MainLoop (main_context);

		var source = new IdleSource ();
		source.set_callback (() => {
			do_perform_operation.begin ();
			return false;
		});
		source.attach (main_context);

		if (loop != null) {
			loop.run ();
		} else {
			mutex.lock ();
			while (!completed)
				cond.wait (mutex);
			mutex.unlock ();
		}

		cancellable.set_error_if_cancelled ();

		if (error != null)
			throw_api_error (error);

		return result;
	}

	private async void do_perform_operation () {
		try {
			result = yield perform_operation ();
		} catch (GLib.Error e) {
			error = e;
		}

		if (loop != null) {
			loop.quit ();
		} else {
			mutex.lock ();
			completed = true;
			cond.signal ();
			mutex.unlock ();
		}
	}

	protected abstract async T perform_operation () throws Error, IOError;

	// FIXME: Work around Vala compiler bug where it fails to include telco-core.h
	[CCode (cname = "telco_get_main_context")]
	private extern static unowned MainContext get_main_context ();
}
