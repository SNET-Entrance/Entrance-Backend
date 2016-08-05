package rest;

import org.restlet.Application;
import org.restlet.Restlet;
import org.restlet.routing.Router;
import org.restlet.routing.TemplateRoute;
import org.restlet.routing.Variable;
import rest.resources.encryptionApi.EncryptionResource;

import java.util.Map;

public class EncryptionAPI extends Application {

    /**
     * Creates a root Restlet that will receive all incoming calls.
     */
    @Override
    public synchronized Restlet createInboundRoot() {
        Router router = new Router(getContext());

        TemplateRoute route = router.attach("/{containerId}", EncryptionResource.class);
        Map<String, Variable> routeVariables = route.getTemplate().getVariables();
        routeVariables.put("containerId", new Variable(Variable.TYPE_DIGIT));

        return router;
    }
}
